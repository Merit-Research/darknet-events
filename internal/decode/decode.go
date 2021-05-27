package decode

import (
	"darknet-events/internal/analysis"
	"net"

	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Decoder is a wrapper around gopacket's DecodingLayerParser that holds useful
// variables for ease of use.
type Decoder struct {
	eth      layers.Ethernet
	ip4      layers.IPv4
	ip6      layers.IPv6
	icmp4    layers.ICMPv4
	icmp6    layers.ICMPv6
	tcp      layers.TCP
	udp      layers.UDP
	//sip      layers.SIP
	//dns      layers.DNS
	//ntp      layers.NTP
	pay      gopacket.Payload
	parser   *gopacket.DecodingLayerParser
	types    []gopacket.LayerType
	unknowns map[string]uint
}

// NewDecoder allocates and initialises a new Decoder.
func NewDecoder() *Decoder {
	d := new(Decoder)
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp, &d.pay)
		//&d.sip, &d.dns, &d.ntp, &d.pay)
	d.types = make([]gopacket.LayerType, 10, 10)
	d.parser.IgnoreUnsupported = true
	d.unknowns = make(map[string]uint)
	return d
}

// Decode runs gopacket's DecodingLayerParser on a packet and parses the
// derived information into event data, packet data, and a timestamp.
func (d *Decoder) Decode(read []byte,
	meta gopacket.CaptureInfo) (analysis.EventSignature, net.IP, time.Time) {

	err := d.parser.DecodeLayers(read, &d.types)

	isErr := false

	if err != nil {
		ult, ok := err.(gopacket.UnsupportedLayerType)
		if ok {
			d.unknowns[gopacket.LayerType(ult).String()]++
		}

		isErr = true
	}

	// TODO: Hack to get around the ETHERNET, IPV4, [NOTHING] case.
	if isErr || len(d.types) < 3 {
		var es analysis.EventSignature
		var ip net.IP

		if d.ip4.DstIP.To4() != nil {
			es = analysis.NewEventSignatureIPv4(d.ip4.SrcIP,
				0, analysis.UnknownTraffic)
			ip = d.ip4.DstIP.To4()
		} else {
			es = analysis.NewEventSignatureIPv6(d.ip6.SrcIP,
				0, analysis.UnknownTraffic)
			ip = d.ip4.DstIP.To16()
		}
		t := meta.Timestamp

		return es, ip, t
	}

	var port uint16
	var traffic analysis.TrafficType
	var transport gopacket.LayerType

	if d.types[1] == layers.LayerTypeIPv4 {
		// for v4 packets, assume that the third element is the transport layer
		transport = d.types[2]
		if transport == layers.LayerTypeIPv6 || transport == layers.LayerTypeIPv4 {
			// this is the case where this is a 6to4 packet or IP-in-IP
			// these packets are effectively ignored to preserve previous
			// functionality and may be changed in the future
			es := analysis.NewEventSignatureIPv4(d.ip4.SrcIP,
				0, analysis.UnknownTraffic)
			ip := d.ip4.DstIP.To4()
			t := meta.Timestamp
			return es, ip, t
		}
	} else if d.types[1] == layers.LayerTypeIPv6 {
		// for v6 packets, loop through to find the transport layer
		// this is due to the fact that valid v6 packets can have any number of
		// HOPOPT headers
		for _, ele := range d.types {
			switch ele {
			case layers.LayerTypeICMPv4:
				fallthrough
			case layers.LayerTypeICMPv6:
				fallthrough
			case layers.LayerTypeTCP:
				fallthrough
			case layers.LayerTypeUDP:
				transport = ele
				break
			default:
				continue
			}
		}
	}

	// Since IP is at the third layer among the four layers (physical, link,
	// ip, and transportation) on which we focus, we look at d.types[2]
	switch transport {
	case layers.LayerTypeICMPv6:
		port = 0
		switch d.icmp6.TypeCode.Type() {
		/*
			https://tools.ietf.org/html/rfc4443
			ICMPv6 is used by IPv6 nodes to report errors encountered in
		    processing packets, and to perform other internet-layer functions,
			such as diagnostics (ICMPv6 "ping").
			*/
		// https://github.com/google/gopacket/blob/a9779d139771f6a06fc983b18e0efd23ca30222f/layers/icmp6.go#L19
		case layers.ICMPv6TypeDestinationUnreachable:
			traffic = analysis.ICMPDestinationUnreachable
		case layers.ICMPv6TypeTimeExceeded:
			traffic = analysis.ICMPTimeExceeded
		case layers.ICMPv6TypeParameterProblem:
			traffic = analysis.ICMPParameterProblem
		case layers.ICMPv6TypeEchoRequest:
			traffic = analysis.ICMPEchoRequest
		case layers.ICMPv6TypeEchoReply:
			traffic = analysis.ICMPEchoReply
		case layers.ICMPv6TypeRedirect:
			traffic = analysis.ICMPRedirect
		default:
			traffic = analysis.ICMPOther
		}
	case layers.LayerTypeICMPv4:
		port = 0
		switch d.icmp4.TypeCode.Type() {
		case layers.ICMPv4TypeEchoRequest:
			traffic = analysis.ICMPEchoRequest
		case layers.ICMPv4TypeEchoReply:
			traffic = analysis.ICMPEchoReply
		case layers.ICMPv4TypeDestinationUnreachable:
			traffic = analysis.ICMPDestinationUnreachable
		case layers.ICMPv4TypeSourceQuench:
			traffic = analysis.ICMPSourceQuench
		case layers.ICMPv4TypeRedirect:
			traffic = analysis.ICMPRedirect
		case layers.ICMPv4TypeTimeExceeded:
			traffic = analysis.ICMPTimeExceeded
		case layers.ICMPv4TypeParameterProblem:
			traffic = analysis.ICMPParameterProblem
		case layers.ICMPv4TypeTimestampReply:
			traffic = analysis.ICMPTimestampReply
		case layers.ICMPv4TypeInfoReply:
			traffic = analysis.ICMPInfoReply
		case layers.ICMPv4TypeAddressMaskReply:
			traffic = analysis.ICMPAddressMaskReply
		default:
			traffic = analysis.ICMPOther
		}
	case layers.LayerTypeTCP:
		otherFlags := d.tcp.FIN || d.tcp.PSH || d.tcp.URG ||
			d.tcp.ECE || d.tcp.CWR || d.tcp.NS
		if !d.tcp.ACK && d.tcp.SYN && !d.tcp.RST && !otherFlags {
			traffic = analysis.TCPSYN
			port = uint16(d.tcp.DstPort)
		} else if d.tcp.ACK && d.tcp.SYN && !d.tcp.RST && !otherFlags {
			traffic = analysis.TCPSYNACK
			port = uint16(d.tcp.SrcPort)
		} else if d.tcp.ACK && !d.tcp.SYN && !d.tcp.RST && !otherFlags {
			traffic = analysis.TCPACK
			port = uint16(d.tcp.DstPort)
		} else if !d.tcp.ACK && !d.tcp.SYN && d.tcp.RST && !otherFlags {
			traffic = analysis.TCPRST
			port = uint16(d.tcp.SrcPort)
		} else {
			traffic = analysis.TCPOther
			// Default port is dest port.
			port = uint16(d.tcp.DstPort)
		}
	case layers.LayerTypeUDP:
		port = uint16(d.udp.DstPort)
		traffic = analysis.UDP
	default:
		// Shouldn't be reached (should be classified as unknown above).
		log.Println("Unknown transport layer:", d.types[2].String())
	}

	var es analysis.EventSignature
	var ip net.IP

	if d.ip4.DstIP.To4() != nil {
		es = analysis.NewEventSignatureIPv4(d.ip4.SrcIP, port, traffic)
		ip = d.ip4.DstIP.To4()
	} else {
		es = analysis.NewEventSignatureIPv6(d.ip6.SrcIP, port, traffic)
		ip = d.ip6.DstIP.To16()
	}
	t := meta.Timestamp

	return es, ip, t
}

// Close prints statistics on the unknown packets and returns.
func (d *Decoder) Close() {
	for k, v := range d.unknowns {
		log.Println(k, v)
	}
}
