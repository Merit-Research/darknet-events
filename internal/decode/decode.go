package decode

import (
	"darknet-events/internal/analysis"

	"encoding/binary"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Decoder is a wrapper around gopacket's DecodingLayerParser that holds useful
// variables for ease of use.
type Decoder struct {
	eth   layers.Ethernet
	ip4   layers.IPv4
	icmp4 layers.ICMPv4
	tcp   layers.TCP
	udp   layers.UDP
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
		&d.eth, &d.ip4, &d.icmp4, &d.tcp, &d.udp,
		&d.pay)
	//&d.sip, &d.dns, &d.ntp, &d.pay)
	d.types = make([]gopacket.LayerType, 4, 4)
	d.parser.IgnoreUnsupported = true
	d.unknowns = make(map[string]uint)
	return d
}

// Decode runs gopacket's DecodingLayerParser on a packet and parses the
// derived information into event data, packet data, and a timestamp.
func (d *Decoder) Decode(read []byte,
	meta gopacket.CaptureInfo) (*analysis.EventSignature, uint32, time.Time) {

	err := d.parser.DecodeLayers(read, &d.types)

	if err != nil {
		ult, ok := err.(gopacket.UnsupportedLayerType)
		if ok {
			d.unknowns[gopacket.LayerType(ult).String()]++
		}
		es := analysis.NewEventSignature(d.ip4.SrcIP,
			0, analysis.UnknownTraffic)
		// The darknet only saves IPv4 packets so calling To4() is safe.
		ip := binary.BigEndian.Uint32(d.ip4.DstIP.To4())
		t := meta.Timestamp

		return es, ip, t
	}

	// TODO: Hack to get around the ETHERNET, IPV4, [NOTHING] case.
	if len(d.types) < 3 {
		es := analysis.NewEventSignature(d.ip4.SrcIP,
			0, analysis.UnknownTraffic)
		ip := binary.BigEndian.Uint32(d.ip4.DstIP.To4())
		t := meta.Timestamp

		return es, ip, t
	}

	var port uint16
	var traffic analysis.TrafficType

	switch d.types[2] {
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
	case layers.LayerTypeIPv4:
		// This handles the IP-IP case (encapsulated IP packets)
		traffic = analysis.UnknownTraffic
		port = 0
		packet := gopacket.NewPacket(read, layers.LayerTypeEthernet, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ip4, ok := ipLayer.(*layers.IPv4) // Doing the necessary casting, because ipLayer is just an interface
		if !ok {
			// Shouldn't be reached since there must be a valid outer IP header,
			// otherwise this packet would not have reached our Darknet
			log.Println("Error decoding outer IPv4 header of IP-IP (proto 4) packet.")
		}
		// log.Println("Outer IPv4 layer of IP-IP packet:", d.types[2].String(), ip4.SrcIP)

		es := analysis.NewEventSignature(ip4.SrcIP, port, traffic)
		ip := binary.BigEndian.Uint32(ip4.DstIP.To4())
		t := meta.Timestamp

		return es, ip, t
	default:
		// Shouldn't be reached (should be classified as unknown above).
		traffic = analysis.UnknownTraffic
		log.Println("Unknown transport layer:", d.types[2].String())
	}

	es := analysis.NewEventSignature(d.ip4.SrcIP, port, traffic)
	ip := binary.BigEndian.Uint32(d.ip4.DstIP.To4())
	t := meta.Timestamp

	return es, ip, t
}

// Close prints statistics on the unknown packets and returns.
func (d *Decoder) Close() {
	for k, v := range d.unknowns {
		log.Println(k, v)
	}
}
