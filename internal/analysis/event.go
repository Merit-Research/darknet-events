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
	SourceIP uint32
	Port     uint16
	Traffic  TrafficType
}

type EventSignatureIPv6 struct {
	SourceIPv6 [16]byte
	Port     uint16
	Traffic  TrafficType
}

func NewEventSignature(sourceIP net.IP,
	p uint16, t TrafficType) *EventSignature {
	var es EventSignature

	// The darknet only saves IPv4 packets so calling To4() is safe.
	sourceIPInt := binary.BigEndian.Uint32(sourceIP.To4())
	es = EventSignature{SourceIP: sourceIPInt, Port: p, Traffic: t}
	return &es
}

// EventPackets collects the data pulled from multiple packets of the same
// event.
type EventPackets struct {
	Dests   *set.Uint32Set
	First   time.Time
	Latest  time.Time
	Packets uint64
	Bytes   uint64
	Samples [][]byte
}

// NewEventPackets returns a new EventPackets object.
func NewEventPackets() *EventPackets {
	ep := new(EventPackets)
	ep.Dests = set.NewUint32Set()
	ep.Samples = make([][]byte, 0, 1)
	return ep
}

// Add adds the destination IP to the packet collection object and returns the
// index it would have been added at (they're actually added to a set).
func (ep *EventPackets) Add(ip uint32, b uint64, t time.Time) int {
	ep.Dests.Add(ip)
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
	size += uintptr(ep.Dests.ByteSize())
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
