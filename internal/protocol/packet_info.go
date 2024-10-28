package protocol

import "time"

// AckedPacketInfo stores information about a successfully acknowledged packet.
// This structure is used to record details of packets that have been acknowledged by the receiver.
type AckedPacketInfo struct {
	PacketNumber PacketNumber
	BytesAcked   ByteCount
	ReceivedTime time.Time
}

// LostPacketInfo stores information about a packet that has been marked as lost.
// This structure helps track details of packets detected as lost during the transmission.
type LostPacketInfo struct {
	PacketNumber PacketNumber
	BytesLost    ByteCount
}
