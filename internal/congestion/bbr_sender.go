package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"

	"golang.org/x/exp/constraints"
)

// BbrSender implements BBR congestion control algorithm. BBR aims to estimate
// the current available Bottleneck Bandwidth and RTT (hence the name), and
// regulates the pacing rate and the size of the congestion window based on
// those signals.
//
// BBR relies on pacing in order to function properly. Do not use BBR when
// pacing is disabled.
//

const (
	// Constants based on TCP defaults.
	// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
	// Does not inflate the pacing rate.
	defaultMinimumCongestionWindow = protocol.ByteCount(protocol.InitialPacketSize << 2)

	// The gain used for the STARTUP, equal to 2/ln(2).
	defaultHighGain = 2.885
	// The newly derived CWND gain for STARTUP, 2.
	derivedHighCWNDGain = 2.0

	// The default RTT used before an RTT sample is taken.
	defaultInitialRTT = 100 * time.Millisecond
)

// PacingGain defines the pacing gain values for each phase of the
// BBR algorithm's bandwidth probing cycle.
var PacingGain = [...]float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	// The length of the gain cycle.
	gainCycleLength = len(PacingGain)
	// The size of the bandwidth filter window, in round-trips.
	bandwidthWindowSize = gainCycleLength + 2

	// The time after which the current min_rtt value expires.
	minRttExpiry = 10 * time.Second
	// The minimum time the connection can spend in PROBE_RTT mode.
	probeRttTime = 200 * time.Millisecond
	// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
	// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
	// will exit the STARTUP mode.
	startupGrowthTarget                         = 1.25
	roundTripsWithoutGrowthBeforeExitingStartup = int64(3)

	// Default parameters for the BBR congestion control algorithm.
	defaultStartupFullLossCount  = 8
	quicBbr2DefaultLossThreshold = 0.02
	maxBbrBurstPackets           = 3
)

type bbrMode int

const (
	// Startup phase of the connection.
	bbrModeStartup = iota
	// After achieving the highest possible bandwidth during the startup, lower
	// the pacing rate in order to drain the queue.
	bbrModeDrain
	// Cruising mode.
	bbrModeProbeBw
	// Temporarily slow down sending in order to empty the buffer and measure
	// the real minimum RTT.
	bbrModeProbeRtt
)

// Indicates how the congestion control limits the amount of bytes in flight.
type bbrRecoveryState int

const (
	// Not in recovery mode; no restrictions on the congestion window.
	bbrRecoveryStateNotInRecovery = iota
	// Allow an extra outstanding byte for each byte acknowledged.
	bbrRecoveryStateConservation
	// Allow two extra outstanding bytes for each byte acknowledged (slow
	// start).
	bbrRecoveryStateGrowth
)

type bbrSender struct {
	rttStats *utils.RTTStats
	clock    Clock
	rand     utils.Rand
	pacer    *pacer

	// Current operational mode of the BBR congestion control algorithm.
	mode bbrMode

	// Bandwidth sampler provides BBR with the bandwidth measurements at
	// individual points.
	sampler *bandwidthSampler

	// The number of the round trips that have occurred during the connection.
	roundTripCount roundTripCount

	// Acknowledgement of any packet after |current_round_trip_end_| will cause
	// the round trip counter to advance.
	currentRoundTripEnd protocol.PacketNumber

	// Number of congestion events with some losses, in the current round.
	numLossEventsInRound uint64

	// Number of total bytes lost in the current round.
	bytesLostInRound protocol.ByteCount

	// The filter that tracks the maximum bandwidth over the multiple recent
	// round-trips.
	maxBandwidth *WindowedFilter[Bandwidth, roundTripCount]

	// Minimum RTT estimate. Automatically expires within 10 seconds (and
	// triggers PROBE_RTT mode) if no new value is sampled during that period.
	minRtt time.Duration
	// The time at which the current value of |min_rtt_| was assigned.
	minRttTimestamp time.Time

	// The maximum allowed number of bytes in flight.
	congestionWindow protocol.ByteCount

	// The initial value of the |congestion_window_|.
	initialCongestionWindow protocol.ByteCount

	// The largest value the |congestion_window_| can achieve.
	maxCongestionWindow protocol.ByteCount

	// The smallest value the |congestion_window_| can achieve.
	minCongestionWindow protocol.ByteCount

	// The pacing gain applied during the STARTUP phase.
	highGain float64

	// The CWND gain applied during the STARTUP phase.
	highCwndGain float64

	// The pacing gain applied during the DRAIN phase.
	drainGain float64

	// The gain currently applied to the pacing rate.
	pacingGain float64
	// The gain currently applied to the congestion window.
	congestionWindowGain float64

	// The gain used for the congestion window during PROBE_BW. Latched from
	// quic_bbr_cwnd_gain flag.
	congestionWindowGainConstant float64
	// The number of RTTs to stay in STARTUP mode.
	numStartupRtts int64

	// Number of round-trips in PROBE_BW mode, used for determining the current
	// pacing gain cycle.
	cycleCurrentOffset int
	// The time at which the last pacing gain cycle was started.
	lastCycleStart time.Time

	// Indicates whether the connection has reached the full bandwidth mode.
	isAtFullBandwidth bool
	// Number of rounds during which there was no significant bandwidth increase.
	roundsWithoutBandwidthGain int64
	// The bandwidth compared to which the increase is measured.
	bandwidthAtLastRound Bandwidth

	// Set to true upon exiting quiescence.
	exitingQuiescence bool

	// Time at which PROBE_RTT has to be exited. Setting it to zero indicates
	// that the time is yet unknown as the number of packets in flight has not
	// reached the required value.
	exitProbeRttAt time.Time
	// Indicates whether a round-trip has passed since PROBE_RTT became active.
	probeRttRoundPassed bool

	// Indicates whether the most recent bandwidth sample was marked as
	// app-limited.
	lastSampleIsAppLimited bool

	// Current state of recovery.
	recoveryState bbrRecoveryState
	// Receiving acknowledgement of a packet after |end_recovery_at_| will cause
	// BBR to exit the recovery mode. A value above zero indicates at least one
	// loss has been detected, so it must not be set back to zero.
	endRecoveryAt protocol.PacketNumber
	// A window used to limit the number of bytes in flight during loss recovery.
	recoveryWindow protocol.ByteCount

	// When true, add the most recent ack aggregation measurement during STARTUP.
	enableAckAggregationDuringStartup bool
	// When true, expire the windowed ack aggregation values in STARTUP when
	// bandwidth increases more than 25%.
	expireAckAggregationInStartup bool

	// If true, will not exit low gain mode until bytes_in_flight drops below BDP
	// or it's time for high gain mode.
	drainToTarget bool

	// Maximum size of a single datagram that can be sent.
	maxDatagramSize protocol.ByteCount

	// Packet information related to the most recent transmission events.
	lastSentPacket   protocol.PacketNumber
	bytesInFlight    protocol.ByteCount
	ackedPacketsInfo []PacketInfo
	lostPacketsInfo  []PacketInfo
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

type PacketInfo struct {
	PacketNumber protocol.PacketNumber
	ByteCount    protocol.ByteCount
}

func NewBbrSender(rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount) *bbrSender {
	b := &bbrSender{
		clock:                        DefaultClock{},
		rttStats:                     rttStats,
		mode:                         bbrModeStartup,
		sampler:                      newBandwidthSampler(roundTripCount(bandwidthWindowSize)),
		lastSentPacket:               protocol.InvalidPacketNumber,
		currentRoundTripEnd:          protocol.InvalidPacketNumber,
		maxBandwidth:                 NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth]),
		congestionWindow:             initialCongestionWindow * initialMaxDatagramSize,
		initialCongestionWindow:      initialCongestionWindow * initialMaxDatagramSize,
		maxCongestionWindow:          protocol.MaxCongestionWindowPackets * initialMaxDatagramSize,
		minCongestionWindow:          defaultMinimumCongestionWindow,
		highGain:                     defaultHighGain,
		highCwndGain:                 defaultHighGain,
		drainGain:                    1.0 / defaultHighGain,
		pacingGain:                   1.0,
		congestionWindowGain:         1.0,
		congestionWindowGainConstant: 2.0,
		numStartupRtts:               roundTripsWithoutGrowthBeforeExitingStartup,
		recoveryState:                bbrRecoveryStateNotInRecovery,
		endRecoveryAt:                protocol.InvalidPacketNumber,
		recoveryWindow:               protocol.MaxCongestionWindowPackets * initialMaxDatagramSize,
		maxDatagramSize:              initialMaxDatagramSize,
	}
	b.pacer = newPacer(b.BandwidthEstimate)

	// Switch to startup mode to probe for bandwidth.
	b.enterStartupMode(b.clock.Now())

	// Set a high congestion window gain for aggressive bandwidth usage.
	b.setHighCwndGain(derivedHighCWNDGain)

	return b
}

func (b *bbrSender) BandwidthEstimate() Bandwidth {
	rtt := b.rttStats.SmoothedRTT()
	if rtt == 0 {
		rtt = 100 * time.Millisecond
	}

	return BandwidthFromDelta(Max(b.congestionWindow, b.maxDatagramSize), rtt)
}

func (b *bbrSender) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytesSent protocol.ByteCount, isRetransmittable bool) {
	// Notify the pacer about the sent packet.
	b.pacer.SentPacket(sentTime, bytesSent)

	// Update the last sent packet and bytes in flight.
	b.lastSentPacket = packetNumber
	b.bytesInFlight = bytesInFlight

	// Handle quiescence state.
	if bytesInFlight == 0 {
		b.exitingQuiescence = true
	}

	// Notify the sampler about the sent packet.
	b.sampler.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytesSent, isRetransmittable)
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *bbrSender) MaybeExitSlowStart() {
	return
}

func (b *bbrSender) OnPacketAcked(packetNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, ackedTime time.Time) {
	b.bytesInFlight -= ackedBytes

	// Record the acknowledgment information.
	b.ackedPacketsInfo = append(b.ackedPacketsInfo, PacketInfo{
		PacketNumber: packetNumber,
		ByteCount:    ackedBytes,
	})
}

func (b *bbrSender) OnAckEventEnd(priorInFlight protocol.ByteCount, eventTime time.Time) {
	totalBytesAckedBefore := b.sampler.TotalBytesAcked()
	totalBytesLostBefore := b.sampler.TotalBytesLost()

	var isRoundStart, minRttExpired bool
	var excessAcked, bytesLost protocol.ByteCount

	// The send state of the largest packet in acked_packets, unless it is
	// empty. If acked_packets is empty, it's the send state of the largest
	// packet in lost_packets.
	var lastPacketSendState sendTimeState

	// Checks if the sender is application-limited based on prior in-flight
	// bytes and updates the sampler.
	b.maybeApplimited(priorInFlight)

	if len(b.ackedPacketsInfo) != 0 {
		lastAckedPacket := b.ackedPacketsInfo[len(b.ackedPacketsInfo)-1].PacketNumber
		isRoundStart = b.updateRoundTripCounter(lastAckedPacket)
		b.updateRecoveryState(lastAckedPacket, len(b.lostPacketsInfo) != 0, isRoundStart)
	}

	sample := b.sampler.OnCongestionEvent(eventTime,
		b.ackedPacketsInfo, b.lostPacketsInfo, b.maxBandwidth.GetBest(), infBandwidth, b.roundTripCount)
	if sample.lastPacketSendState.isValid {
		b.lastSampleIsAppLimited = sample.lastPacketSendState.isAppLimited
	}

	// Avoid updating |max_bandwidth_| if a) this is a loss-only event, or b) all
	// packets in |acked_packets| did not generate valid samples. (e.g. ack of
	// ack-only packets). In both cases, sampler_.total_bytes_acked() will not
	// change.
	if totalBytesAckedBefore != b.sampler.TotalBytesAcked() {
		if !sample.sampleIsAppLimited || sample.sampleMaxBandwidth > b.maxBandwidth.GetBest() {
			b.maxBandwidth.Update(sample.sampleMaxBandwidth, b.roundTripCount)
		}
	}

	if sample.sampleRtt != infRTT {
		minRttExpired = b.maybeUpdateMinRtt(eventTime, sample.sampleRtt)
	}

	// Calculates the bytes lost during the current period.
	bytesLost = b.sampler.TotalBytesLost() - totalBytesLostBefore

	// The number of extra bytes acked from this ack event, compared to what is
	// expected from the flow's bandwidth. Larger value means more ack
	// aggregation.
	excessAcked = sample.extraAcked

	// The send state of the largest packet in acked_packets, unless it is
	// empty. If acked_packets is empty, it's the send state of the largest
	// packet in lost_packets.
	lastPacketSendState = sample.lastPacketSendState

	if len(b.lostPacketsInfo) != 0 {
		// Number of congestion events with some losses, in the current round.
		b.numLossEventsInRound++
		// Number of total bytes lost in the current round.
		b.bytesLostInRound += bytesLost
	}

	// Handle logic specific to PROBE_BW mode.
	if b.mode == bbrModeProbeBw {
		b.updateGainCyclePhase(
			eventTime,
			priorInFlight,
			len(b.lostPacketsInfo) != 0,
		)
	}

	// Handle logic specific to STARTUP and DRAIN modes.
	if isRoundStart && !b.isAtFullBandwidth {
		b.checkIfFullBandwidthReached(&lastPacketSendState)
	}

	b.maybeExitStartupOrDrain(eventTime)

	// Handle logic specific to PROBE_RTT.
	b.maybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired)

	// Calculate number of packets acked and lost.
	bytesAcked := b.sampler.TotalBytesAcked() - totalBytesAckedBefore

	// After the model is updated, recalculate the pacing rate and congestion
	// window.
	b.calculateCongestionWindow(bytesAcked, excessAcked)
	b.calculateRecoveryWindow(bytesAcked, bytesLost)

	if len(b.lostPacketsInfo) != 0 {
		b.sampler.RemoveObsoletePackets(
			b.lostPacketsInfo[len(b.lostPacketsInfo)-1].PacketNumber,
		)
	}

	if len(b.ackedPacketsInfo) != 0 {
		bias := protocol.PacketNumber(b.calculateUselessAckBias())
		if uselessPacketNum := b.ackedPacketsInfo[0].PacketNumber - bias; uselessPacketNum > 0 {
			b.sampler.RemoveObsoletePackets(uselessPacketNum)
		}
	}

	if isRoundStart {
		// Number of congestion events with some losses, in the current round.
		b.numLossEventsInRound = 0
		// Number of total bytes lost in the current round.
		b.bytesLostInRound = 0
	}

	b.ackedPacketsInfo = nil
	b.lostPacketsInfo = nil
}

func (b *bbrSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	if lostBytes > 0 {
		b.bytesInFlight -= lostBytes

		b.lostPacketsInfo = append(b.lostPacketsInfo, PacketInfo{
			PacketNumber: packetNumber,
			ByteCount:    lostBytes,
		})
	}
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	return
}

func (b *bbrSender) SetMaxDatagramSize(size protocol.ByteCount) {
	// Ignore if the new size is smaller than the current maximum datagram size.
	if size < b.maxDatagramSize {
		return
	}

	// Update the maximum datagram size.
	b.maxDatagramSize = size

	// Notify the pacer about the new datagram size.
	b.pacer.SetMaxDatagramSize(size)
}

func (b *bbrSender) InSlowStart() bool {
	return b.mode == bbrModeStartup
}

func (b *bbrSender) InRecovery() bool {
	return b.recoveryState != bbrRecoveryStateNotInRecovery
}

func (b *bbrSender) GetCongestionWindow() protocol.ByteCount {
	// If in ProbeRtt mode, use the ProbeRtt-specific congestion window.
	if b.mode == bbrModeProbeRtt {
		return Max(b.probeRttCongestionWindow(), b.maxDatagramSize)
	}

	// If in recovery mode with a valid recovery window, limit to the smaller of
	// the congestion window and recovery window.
	if b.InRecovery() && b.recoveryWindow > 0 {
		return Max(Min(b.congestionWindow, b.recoveryWindow), b.maxDatagramSize)
	}

	// Default to congestion window, ensuring it's at least maxDatagramSize.
	return Max(b.congestionWindow, b.maxDatagramSize)
}

func (b *bbrSender) setHighCwndGain(highCwndGain float64) {
	b.highCwndGain = highCwndGain

	if b.mode == bbrModeStartup {
		b.congestionWindowGain = highCwndGain
	}
}

func (b *bbrSender) bandwidthEstimate() Bandwidth {
	rtt := b.rttStats.SmoothedRTT()
	if rtt == 0 {
		// If we haven't measured an rtt, the bandwidth estimate is unknown.
		return infBandwidth
	}

	bandwidth := b.maxBandwidth.GetBest()
	if bandwidth == 0 {
		return infBandwidth
	}

	return bandwidth
}

func (b *bbrSender) getMinRtt() time.Duration {
	minRtt := b.minRtt
	if minRtt != 0 {
		return minRtt
	}

	// min_rtt could be available if the handshake packet gets neutered then
	// gets acknowledged. This could only happen for QUIC crypto where we do not
	// drop keys.
	minRtt = b.rttStats.MinRTT()
	if minRtt != 0 {
		return minRtt
	}

	return defaultInitialRTT
}

func (b *bbrSender) getTargetCongestionWindow(gain float64) protocol.ByteCount {
	bdp := bdpFromRttAndBandwidth(b.getMinRtt(), b.bandwidthEstimate())

	congestionWindow := protocol.ByteCount(float64(bdp) * gain)
	if congestionWindow == 0 {
		congestionWindow = protocol.ByteCount(float64(b.initialCongestionWindow) * gain)
	}

	return Max(congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) probeRttCongestionWindow() protocol.ByteCount {
	return b.minCongestionWindow
}

func (b *bbrSender) maybeUpdateMinRtt(now time.Time, sampleMinRtt time.Duration) bool {
	minRttExpired := b.minRtt != 0 && now.After(b.minRttTimestamp.Add(minRttExpiry))

	if minRttExpired || sampleMinRtt < b.minRtt || b.minRtt == 0 {
		// Minimum RTT expires automatically after 10 seconds.
		b.minRtt = sampleMinRtt
		// The time at which the current value was assigned.
		b.minRttTimestamp = now
	}

	return minRttExpired
}

func (b *bbrSender) enterStartupMode(now time.Time) {
	b.mode = bbrModeStartup
	b.pacingGain = b.highGain
	b.congestionWindowGain = b.highCwndGain
}

func (b *bbrSender) enterProbeBandwidthMode(now time.Time) {
	b.mode = bbrModeProbeBw
	b.congestionWindowGain = b.congestionWindowGainConstant

	// Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
	// excluded because in that case increased gain and decreased gain would not
	// follow each other.
	b.cycleCurrentOffset = int(b.rand.Int31n(protocol.PacketsPerConnectionID)) % (gainCycleLength - 1)
	if b.cycleCurrentOffset >= 1 {
		b.cycleCurrentOffset += 1
	}

	b.lastCycleStart = now
	b.pacingGain = PacingGain[b.cycleCurrentOffset]
}

func (b *bbrSender) updateRoundTripCounter(lastAckedPacket protocol.PacketNumber) bool {
	if b.currentRoundTripEnd == protocol.InvalidPacketNumber || lastAckedPacket > b.currentRoundTripEnd {
		b.roundTripCount++
		b.currentRoundTripEnd = b.lastSentPacket
		return true
	}

	return false
}

func (b *bbrSender) updateGainCyclePhase(now time.Time, priorInFlight protocol.ByteCount, hasLosses bool) {
	// In most cases, the cycle is advanced after an RTT passes.
	shouldAdvanceGainCycling := now.After(b.lastCycleStart.Add(b.getMinRtt()))

	// If the pacing gain is above 1.0, the connection is trying to probe the
	// bandwidth by increasing the number of bytes in flight to at least
	// pacing_gain * BDP. Make sure that it actually reaches the target, as long
	// as there are no losses suggesting that the buffers are not able to hold
	// that much.
	if b.pacingGain > 1.0 && !hasLosses && priorInFlight < b.getTargetCongestionWindow(b.pacingGain) {
		shouldAdvanceGainCycling = false
	}

	// If pacing gain is below 1.0, the connection is trying to drain the extra
	// queue which could have been incurred by probing prior to it. If the number
	// of bytes in flight falls down to the estimated BDP value earlier, conclude
	// that the queue has been successfully drained and exit this cycle early.
	if b.pacingGain < 1.0 && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		shouldAdvanceGainCycling = true
	}

	if shouldAdvanceGainCycling {
		b.cycleCurrentOffset = (b.cycleCurrentOffset + 1) % gainCycleLength
		b.lastCycleStart = now

		// Stay in low gain mode until the target BDP is hit.
		// Low gain mode will be exited immediately when the target BDP is achieved.
		if b.drainToTarget && b.pacingGain < 1 &&
			PacingGain[b.cycleCurrentOffset] == 1 &&
			b.bytesInFlight > b.getTargetCongestionWindow(1) {
			return
		}

		b.pacingGain = PacingGain[b.cycleCurrentOffset]
	}
}

func (b *bbrSender) checkIfFullBandwidthReached(lastPacketSendState *sendTimeState) {
	// Exit if the last sample was application-limited.
	if b.lastSampleIsAppLimited {
		return
	}

	// Check if the bandwidth has reached the target growth.
	target := Bandwidth(float64(b.bandwidthAtLastRound) * startupGrowthTarget)
	if b.bandwidthEstimate() >= target {
		b.bandwidthAtLastRound = b.bandwidthEstimate()
		b.roundsWithoutBandwidthGain = 0

		if b.expireAckAggregationInStartup {
			b.sampler.ResetMaxAckHeightTracker(0, b.roundTripCount)
		}

		return
	}

	// Increment the counter for rounds without bandwidth gain.
	b.roundsWithoutBandwidthGain++

	// Check if the startup phase should end.
	if b.roundsWithoutBandwidthGain >= b.numStartupRtts ||
		b.shouldExitStartupDueToLoss(lastPacketSendState) {
		b.isAtFullBandwidth = true
	}
}

func (b *bbrSender) maybeApplimited(bytesInFlight protocol.ByteCount) {
	// Get the current congestion window size.
	congestionWindow := b.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return
	}

	// Determine if the connection is drain-limited.
	drainLimited := b.mode == bbrModeDrain && bytesInFlight > congestionWindow/2
	availableBytes := congestionWindow - bytesInFlight

	// Mark as application-limited if conditions are met.
	if !drainLimited || availableBytes > maxBbrBurstPackets*b.maxDatagramSize {
		b.sampler.OnAppLimited()
	}
}

func (b *bbrSender) maybeExitStartupOrDrain(now time.Time) {
	if b.mode == bbrModeStartup && b.isAtFullBandwidth {
		b.mode = bbrModeDrain
		b.pacingGain = b.drainGain
		b.congestionWindowGain = b.highCwndGain
	}

	if b.mode == bbrModeDrain && b.bytesInFlight <= b.getTargetCongestionWindow(1) {
		b.enterProbeBandwidthMode(now)
	}
}

func (b *bbrSender) maybeEnterOrExitProbeRtt(now time.Time, isRoundStart, minRttExpired bool) {
	// Check if conditions to enter PROBE_RTT mode are met.
	if minRttExpired && !b.exitingQuiescence && b.mode != bbrModeProbeRtt {
		b.mode = bbrModeProbeRtt
		b.pacingGain = 1.0

		// Do not decide on the time to exit PROBE_RTT until |bytes_in_flight|
		// reaches the target small value.
		b.exitProbeRttAt = time.Time{}
	}

	if b.mode == bbrModeProbeRtt {
		// Mark the sender as application-limited during PROBE_RTT.
		b.sampler.OnAppLimited()

		if b.exitProbeRttAt.IsZero() {
			// If the window is appropriately small, schedule exiting PROBE_RTT.
			// The CWND during PROBE_RTT is kMinimumCongestionWindow, but we allow
			// an extra packet since QUIC checks CWND before sending a packet.
			if b.bytesInFlight < b.probeRttCongestionWindow()+protocol.MaxPacketBufferSize {
				b.exitProbeRttAt = now.Add(probeRttTime)
				b.probeRttRoundPassed = false
			}
		} else {
			// Check if a round has passed during PROBE_RTT.
			if isRoundStart {
				b.probeRttRoundPassed = true
			}

			// Exit PROBE_RTT mode if conditions are met.
			if now.Sub(b.exitProbeRttAt) >= 0 && b.probeRttRoundPassed {
				b.minRttTimestamp = now
				if !b.isAtFullBandwidth {
					b.enterStartupMode(now)
				} else {
					b.enterProbeBandwidthMode(now)
				}
			}
		}
	}

	b.exitingQuiescence = false
}

func (b *bbrSender) updateRecoveryState(lastAckedPacket protocol.PacketNumber, hasLosses, isRoundStart bool) {
	// Disable recovery in startup, if loss-based exit is enabled.
	if !b.isAtFullBandwidth {
		return
	}

	// Exit recovery when there are no losses for a round.
	if hasLosses {
		b.endRecoveryAt = b.lastSentPacket
	}

	switch b.recoveryState {
	case bbrRecoveryStateNotInRecovery:
		if hasLosses {
			b.recoveryState = bbrRecoveryStateConservation
			// This will cause the |recovery_window_| to be set to the correct
			// value in CalculateRecoveryWindow().
			b.recoveryWindow = 0
			// Since the conservation phase is meant to last for a whole round,
			// extend the current round as if it were started right now.
			b.currentRoundTripEnd = b.lastSentPacket
		}
	case bbrRecoveryStateConservation:
		if isRoundStart {
			b.recoveryState = bbrRecoveryStateGrowth
		}
		fallthrough
	case bbrRecoveryStateGrowth:
		// Exit recovery if appropriate.
		if !hasLosses && lastAckedPacket > b.endRecoveryAt {
			b.recoveryState = bbrRecoveryStateNotInRecovery
		}
	}
}

func (b *bbrSender) calculateCongestionWindow(bytesAcked, excessAcked protocol.ByteCount) {
	// If in ProbeRTT mode, do not adjust the congestion window.
	if b.mode == bbrModeProbeRtt {
		return
	}

	// Calculate the target congestion window based on the current gain.
	targetWindow := b.getTargetCongestionWindow(b.congestionWindowGain)

	if b.isAtFullBandwidth {
		// Add the max recently measured ack aggregation to the target window.
		targetWindow += b.sampler.MaxAckHeight()
	} else if b.enableAckAggregationDuringStartup {
		// In STARTUP, add the most recent excess acked to create a localized max filter.
		targetWindow += excessAcked
	}

	// Gradually grow the congestion window towards the target window.
	if b.isAtFullBandwidth {
		b.congestionWindow = Min(targetWindow, b.congestionWindow+bytesAcked)
	} else if b.congestionWindow < targetWindow ||
		b.sampler.TotalBytesAcked() < b.initialCongestionWindow {
		// Do not decrease the congestion window in STARTUP phase.
		b.congestionWindow += bytesAcked
	}

	// Enforce the minimum and maximum limits on the congestion window.
	b.congestionWindow = Max(b.congestionWindow, b.minCongestionWindow)
	b.congestionWindow = Min(b.congestionWindow, b.maxCongestionWindow)
}

func (b *bbrSender) calculateRecoveryWindow(bytesAcked, bytesLost protocol.ByteCount) {
	if b.recoveryState == bbrRecoveryStateNotInRecovery {
		return
	}

	// Set up the initial recovery window.
	if b.recoveryWindow == 0 {
		b.recoveryWindow = b.bytesInFlight + bytesAcked
		b.recoveryWindow = Max(b.minCongestionWindow, b.recoveryWindow)
		return
	}

	// Remove losses from the recovery window, while accounting for a potential
	// integer underflow.
	if b.recoveryWindow >= bytesLost {
		b.recoveryWindow = b.recoveryWindow - bytesLost
	} else {
		b.recoveryWindow = b.maxDatagramSize
	}

	// In CONSERVATION mode, just subtracting losses is sufficient.
	// In GROWTH mode, release additional |bytes_acked| to achieve a slow-start-like behavior.
	if b.recoveryState == bbrRecoveryStateGrowth {
		b.recoveryWindow += bytesAcked
	}

	// Always allow sending at least |bytes_acked| in response.
	b.recoveryWindow = Max(b.recoveryWindow, b.bytesInFlight+bytesAcked)
	b.recoveryWindow = Max(b.minCongestionWindow, b.recoveryWindow)
}

func (b *bbrSender) shouldExitStartupDueToLoss(lastPacketSendState *sendTimeState) bool {
	if b.numLossEventsInRound < defaultStartupFullLossCount || !lastPacketSendState.isValid {
		return false
	}

	inflightAtSend := lastPacketSendState.bytesInFlight

	if inflightAtSend > 0 && b.bytesLostInRound > 0 {
		return b.bytesLostInRound > protocol.ByteCount(float64(inflightAtSend)*quicBbr2DefaultLossThreshold)
	}

	return false
}

func (b *bbrSender) calculateUselessAckBias() int64 {
	return int64(b.rttStats.PTO(false)) * int64(b.bandwidthEstimate()) / int64(protocol.InitialPacketSize*8) / int64(time.Second)
}

func bdpFromRttAndBandwidth(rtt time.Duration, bandwidth Bandwidth) protocol.ByteCount {
	return protocol.ByteCount(rtt) * protocol.ByteCount(bandwidth) / protocol.ByteCount(BytesPerSecond) / protocol.ByteCount(time.Second)
}

func Min[T constraints.Ordered](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Max[T constraints.Ordered](a, b T) T {
	if a < b {
		return b
	}
	return a
}
