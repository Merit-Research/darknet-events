package analysis

//go:generate msgp

import "log"

// TrafficType is an enumeration of possible traffic types.
type TrafficType uint16

// The following are possible types of traffic.
const (
	ICMPEchoRequest TrafficType = iota
	ICMPEchoReply
	ICMPDestinationUnreachable
	ICMPSourceQuench
	ICMPRedirect
	ICMPTimeExceeded
	ICMPParameterProblem
	ICMPTimestampReply
	ICMPInfoReply
	ICMPAddressMaskReply
	ICMPOther
	TCPSYN
	TCPSYNACK
	TCPACK
	TCPRST
	TCPOther
	UDP
	UnknownTraffic
)

func (t TrafficType) IsTCP() bool {
	switch t {
	case TCPSYN:
		fallthrough
	case TCPSYNACK:
		fallthrough
	case TCPACK:
		fallthrough
	case TCPRST:
		fallthrough
	case TCPOther:
		return true
	default:
		return false
	}
}

func (t TrafficType) IsICMP() bool {
	switch t {
	case ICMPEchoRequest:
		fallthrough
	case ICMPEchoReply:
		fallthrough
	case ICMPDestinationUnreachable:
		fallthrough
	case ICMPSourceQuench:
		fallthrough
	case ICMPRedirect:
		fallthrough
	case ICMPTimeExceeded:
		fallthrough
	case ICMPParameterProblem:
		fallthrough
	case ICMPTimestampReply:
		fallthrough
	case ICMPInfoReply:
		fallthrough
	case ICMPAddressMaskReply:
		fallthrough
	case ICMPOther:
		return true
	default:
		return false
	}
}

func (t TrafficType) ToString() string {
	switch t {
	case ICMPEchoRequest:
		return "ICMPEchoRequest"
	case ICMPEchoReply:
		return "ICMPEchoReply"
	case ICMPDestinationUnreachable:
		return "ICMPDestinationUnreachable"
	case ICMPSourceQuench:
		return "ICMPSourceQuench"
	case ICMPRedirect:
		return "ICMPRedirect"
	case ICMPTimeExceeded:
		return "ICMPTimeExceeded"
	case ICMPParameterProblem:
		return "ICMPParameterProblem"
	case ICMPTimestampReply:
		return "ICMPTimestampReply"
	case ICMPInfoReply:
		return "ICMPInfoReply"
	case ICMPAddressMaskReply:
		return "ICMPAddressMaskReply"
	case ICMPOther:
		return "ICMPOther"
	case TCPSYN:
		return "TCPSYN"
	case TCPSYNACK:
		return "TCPSYNACK"
	case TCPACK:
		return "TCPACK"
	case TCPRST:
		return "TCPRST"
	case TCPOther:
		return "TCPOther"
	case UDP:
		return "UDP"
	case UnknownTraffic:
		return "UnknownTraffic"
	default:
		log.Panic("Encountered unrecognised/unhandled traffic type.")

		// Not reached.
		return "[ERROR] Not Recognised"
	}
}
