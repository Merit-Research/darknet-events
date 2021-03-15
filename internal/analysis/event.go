package analysis

//go:generate msgp

import (
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"darknet-events/internal/set"
)

// EventSignature is the data structure used to associate different packets to
// a single source and/or being of the same event.
type EventSignature struct {
	SourceIPv6 [16]byte
	SourceIPv4 uint32
	Port     uint16
	Traffic  TrafficType
	IsIPv4	 bool
}

// NewEventSignature returns a new EventSignature from the given data.
func NewEventSignature(sourceIP net.IP,
	p uint16, t TrafficType) *EventSignature {
	var es EventSignature

	if sourceIP.To4() != nil {
		sourceIPv4 := binary.BigEndian.Uint32(sourceIP.To4())
		es = EventSignature{
			SourceIPv4: sourceIPv4, Port: p,
			Traffic: t, IsIPv4: true }
	} else {
		var sourceIPv6 [16]byte
		copy(sourceIPv6[:], sourceIP)
		es = EventSignature{
			SourceIPv6: sourceIPv6, Port: p,
			Traffic: t, IsIPv4: false }
	}

	return &es
}

// EventPackets collects the data pulled from multiple packets of the same
// event.
type EventPackets struct {
	DestIPv6   *set.IPSet	// for IPv6
	DestIPv4 *set.Uint32Set // for IPv4
	First   time.Time
	Latest  time.Time
	Packets uint64
	Bytes   uint64
	Samples [][]byte
	IsIPv4  bool
}

// NewEventPackets returns a new EventPackets object.
func NewEventPackets(isIPv4 bool) *EventPackets {
	ep := new(EventPackets)
	if isIPv4 {
		ep.DestIPv4 = set.NewUint32Set()
		ep.IsIPv4 = true
	} else {
		ep.DestIPv6 = set.NewIPSet()
		ep.IsIPv4 = false
	}
	ep.Samples = make([][]byte, 0, 1)
	return ep
}

// Add adds the destination IP to the packet collection object and returns the
// index it would have been added at (they're actually added to a set).
func (ep *EventPackets) Add(destIP net.IP, b uint64, t time.Time) int {
	if ep.IsIPv4 {
		destIPv4 := binary.BigEndian.Uint32(destIP.To4())
		ep.DestIPv4.Add(destIPv4)
	} else {
		var destIPv6 [16]byte
		copy(destIPv6[:], destIP)
		ep.DestIPv6.Add(destIPv6)
	}
	if ep.First.IsZero() {
		ep.First = t
	}
	ep.Latest = t
	ep.Packets++
	ep.Bytes += b
	return int(ep.Packets) - 1
}

/*
// Append appends the given packet to the EventPackets object and returns the
// index that it was appended at.
func (ep *EventPackets) Append(p Packet, t time.Time) int {
	ep.Packets = append(ep.Packets, p)
	if ep.First.IsZero() {
		ep.First = t
	}
	ep.Latest = t
	return len(ep.Packets) - 1
}
*/

// AddSample adds a raw packet to an EventPackets object's collections of
// samples at the given index
func (ep *EventPackets) AddSample(i int, raw []byte) {
	if len(ep.Samples) < i+1 {
		ep.Samples = append(ep.Samples, raw)
	} else {
		ep.Samples[i] = raw
	}
}

// Size returns the number of bytes of memory consumed by the EventPackets
// object.
func (ep *EventPackets) Size() uintptr {
	var size uintptr
	size += unsafe.Sizeof(ep)
	if ep.IsIPv4 {
		size += uintptr(ep.DestIPv4.Size())
	} else {
		size += uintptr(ep.DestIPv6.Size())
	}
	for _, s := range ep.Samples {
		size += uintptr(len(s))
	}
	return size
}

// Event combines an event signature and its collection of packets together.
type Event struct {
	Signature EventSignature
	Packets   *EventPackets
}

// NewEvent creates an Event object from the given EventSignature and
// EventPackets objects.
func NewEvent(es EventSignature, ep *EventPackets) *Event {
	e := Event{Signature: es, Packets: ep}
	return &e
}
