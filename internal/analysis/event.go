package analysis

//go:generate msgp

import (
	"encoding/binary"
	"github.com/tinylib/msgp/msgp"
	"net"
	"time"
	"unsafe"

	"darknet-events/internal/set"
)

type EventSignature interface {
	GetPort() uint16
	GetTraffic() TrafficType

	// Generated by msgp
	DecodeMsg(dc *msgp.Reader) error
	EncodeMsg(en *msgp.Writer) error
	MarshalMsg(o []byte) ([]byte, error)
	UnmarshalMsg(bts []byte) ([]byte, error)
	Msgsize() int
}

// EventSignature is the data structure used to associate different packets to
// a single source and/or being of the same event.
type EventSignatureIPv4 struct {
	SourceIPv4 uint32
	Port     uint16
	Traffic  TrafficType
}

type EventSignatureIPv6 struct {
	SourceIPv6 [16]byte
	Port     uint16
	Traffic  TrafficType
}

func NewEventSignatureIPv4(sourceIP net.IP,
	p uint16, t TrafficType) EventSignatureIPv4 {
	sourceIPv4 := binary.BigEndian.Uint32(sourceIP.To4())

	es := new(EventSignatureIPv4)

	es.SourceIPv4 = sourceIPv4
	es.Port = p
	es.Traffic = t

	return *es
}

func NewEventSignatureIPv6(sourceIP net.IP,
	p uint16, t TrafficType) EventSignatureIPv6 {
	var sourceIPv6 [16]byte
	copy(sourceIPv6[:], sourceIP)

	es := new(EventSignatureIPv6)

	es.SourceIPv6 = sourceIPv6
	es.Port = p
	es.Traffic = t

	return *es
}

func (es EventSignatureIPv4) GetPort() uint16 {
	return es.Port
}

func (es EventSignatureIPv6) GetPort() uint16 {
	return es.Port
}

func (es EventSignatureIPv4) GetTraffic() TrafficType {
	return es.Traffic
}

func (es EventSignatureIPv6) GetTraffic() TrafficType {
	return es.Traffic
}

type EventPackets interface {
	Add(destIP net.IP, b uint64, t time.Time) int
	AddSample(i int, raw []byte)
	Size() uintptr
	GetFirst() time.Time
	GetLatest() time.Time
	GetPackets() uint64
	GetBytes()   uint64
	GetSamples() [][]byte

	// Generated by msgp
	DecodeMsg(dc *msgp.Reader) error
	EncodeMsg(en *msgp.Writer) error
	MarshalMsg(o []byte) ([]byte, error)
	UnmarshalMsg(bts []byte) ([]byte, error)
	Msgsize() int
}

// EventPackets collects the data pulled from multiple packets of the same
// event.
type EventPacketsIPv4 struct {
	DestIPv4 *set.Uint32Set // for IPv4
	First   time.Time
	Latest  time.Time
	Packets uint64
	Bytes   uint64
	Samples [][]byte
}

type EventPacketsIPv6 struct {
	DestIPv6   *set.IPSet	// for IPv6
	First   time.Time
	Latest  time.Time
	Packets uint64
	Bytes   uint64
	Samples [][]byte
}

// NewEventPackets returns a new EventPackets object.
func NewEventPacketsIPv4() *EventPacketsIPv4 {
	ep := new(EventPacketsIPv4)

	ep.DestIPv4 = set.NewUint32Set()
	ep.Samples = make([][]byte, 0, 1)

	return ep
}

func NewEventPacketsIPv6() *EventPacketsIPv6 {
	ep := new(EventPacketsIPv6)

	ep.DestIPv6 = set.NewIPSet()
	ep.Samples = make([][]byte, 0, 1)

	return ep
}

// Add adds the destination IP to the packet collection object and returns the
// index it would have been added at (they're actually added to a set).
func (ep *EventPacketsIPv4) Add(destIP net.IP, b uint64, t time.Time) int {
	destIPv4 := binary.BigEndian.Uint32(destIP.To4())
	ep.DestIPv4.Add(destIPv4)

	if ep.First.IsZero() {
		ep.First = t
	}

	ep.Latest = t
	ep.Packets++
	ep.Bytes += b
	return int(ep.Packets) - 1
}

func (ep *EventPacketsIPv6) Add(destIP net.IP, b uint64, t time.Time) int {
	var destIPv6 [16]byte
	copy(destIPv6[:], destIP)
	ep.DestIPv6.Add(destIPv6)

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
func (ep *EventPacketsIPv4) AddSample(i int, raw []byte) {
	if len(ep.Samples) < i+1 {
		ep.Samples = append(ep.Samples, raw)
	} else {
		ep.Samples[i] = raw
	}
}

func (ep *EventPacketsIPv6) AddSample(i int, raw []byte) {
	if len(ep.Samples) < i+1 {
		ep.Samples = append(ep.Samples, raw)
	} else {
		ep.Samples[i] = raw
	}
}

// Size returns the number of bytes of memory consumed by the EventPackets
// object.
func (ep *EventPacketsIPv4) Size() uintptr {
	var size uintptr
	size += unsafe.Sizeof(ep)
	size += uintptr(ep.DestIPv4.Size())

	for _, s := range ep.Samples {
		size += uintptr(len(s))
	}

	return size
}

func (ep *EventPacketsIPv6) Size() uintptr {
	var size uintptr
	size += unsafe.Sizeof(ep)
	size += uintptr(ep.DestIPv6.Size())

	for _, s := range ep.Samples {
		size += uintptr(len(s))
	}

	return size
}


func (ep *EventPacketsIPv4) GetFirst() time.Time {
	return ep.First
}

func (ep *EventPacketsIPv6) GetFirst() time.Time {
	return ep.First
}

func (ep *EventPacketsIPv4) GetLatest() time.Time {
	return ep.Latest
}

func (ep *EventPacketsIPv6) GetLatest() time.Time {
	return ep.Latest
}

func (ep *EventPacketsIPv4) GetPackets() uint64 {
	return ep.Packets
}

func (ep *EventPacketsIPv6) GetPackets() uint64 {
	return ep.Packets
}

func (ep *EventPacketsIPv4) GetBytes() uint64 {
	return ep.Bytes
}

func (ep *EventPacketsIPv6) GetBytes() uint64 {
	return ep.Bytes
}

func (ep *EventPacketsIPv4) GetSamples() [][]byte {
	return ep.Samples
}

func (ep *EventPacketsIPv6) GetSamples() [][]byte {
	return ep.Samples
}

// Event combines an event signature and its collection of packets together.
type Event struct {
	Signature EventSignature
	Packets   EventPackets
}

// NewEvent creates an Event object from the given EventSignature and
// EventPackets objects.
func NewEvent(es EventSignature, ep EventPackets) *Event {
	e := Event{Signature: es, Packets: ep}
	return &e
}
