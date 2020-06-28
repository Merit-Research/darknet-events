package data

// TrafficType is an enumeration of possible traffic types.
type TrafficType int

// The following are possible types of traffic.
const (
	ICMP TrafficType = iota
	TCP
	UDP
	UnknownTraffic
)

// EventType is an enumeration of possible event types.
type EventType int

// The following are possible types for network events.
const (
	Backscatter EventType = iota
	Scan
	Ignored
	UnknownEvent
)
