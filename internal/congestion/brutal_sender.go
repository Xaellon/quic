package congestion

import (
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	pktInfoSlotCount           = 5 // slot index is based on seconds, so this is basically how many seconds we sample
	minSampleCount             = 50
	minAckRate                 = 0.8
	congestionWindowMultiplier = 2
)

var (
	_ SendAlgorithm               = &BrutalSender{}
	_ SendAlgorithmWithDebugInfos = &BrutalSender{}
)

type BrutalSender struct {
	rttStats        *utils.RTTStats
	bps             protocol.ByteCount
	maxDatagramSize protocol.ByteCount
	pacer           *pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64
}

type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *BrutalSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *BrutalSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *BrutalSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

func (b *BrutalSender) MaybeExitSlowStart() {
	// Stub
}

func (b *BrutalSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	currentTimestamp := eventTime.Unix()
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].AckCount++
	} else {
		// uninitialized slot or too old, reset
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = 1
		b.pktInfoSlots[slot].LossCount = 0
	}
	b.updateAckRate(currentTimestamp)
}

func (b *BrutalSender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	currentTimestamp := time.Now().Unix()
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount++
	} else {
		// uninitialized slot or too old, reset
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = 0
		b.pktInfoSlots[slot].LossCount = 1
	}
	b.updateAckRate(currentTimestamp)
}

func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	// Stub
}

func (b *BrutalSender) SetMaxDatagramSize(size protocol.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

func (b *BrutalSender) InSlowStart() bool {
	return false
}

func (b *BrutalSender) InRecovery() bool {
	return false
}

func (b *BrutalSender) GetCongestionWindow() protocol.ByteCount {
	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return 65536
	}
	cwnd := protocol.ByteCount(float64(b.bps) * rtt.Seconds() * congestionWindowMultiplier / b.ackRate)
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}
	return cwnd
}

// NewBrutalSender makes a new brutal sender
func NewBrutalSender(rttStats *utils.RTTStats) *BrutalSender {
	var bw uint64 = 120
	bwstr, exists := os.LookupEnv("brutal_pacering")
	if exists {
		value, err := strconv.ParseUint(bwstr, 10, 64)
		if err == nil && value > 0 {
			bw = value
		}
	}

	bs := &BrutalSender{
		rttStats:        rttStats,
		bps:             protocol.ByteCount(bw << 17),
		maxDatagramSize: protocol.InitialPacketSize,
		ackRate:         1,
	}
	bs.pacer = newPacer(
		func() Bandwidth {
			return Bandwidth(float64(bs.bps<<3) / bs.ackRate)
		})
	return bs
}

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
	}
	if ackCount+lossCount < minSampleCount {
		b.ackRate = 1
		return
	}
	rate := float64(ackCount) / float64(ackCount+lossCount)
	if rate < minAckRate {
		b.ackRate = minAckRate
		return
	}
	b.ackRate = rate
	return
}
