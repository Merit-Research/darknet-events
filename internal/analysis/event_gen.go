package analysis

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"darknet-events/internal/set"

	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *Event) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zxvk uint32
	zxvk, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zxvk > 0 {
		zxvk--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Signature":
			var zbzg uint32
			zbzg, err = dc.ReadMapHeader()
			if err != nil {
				return
			}
			for zbzg > 0 {
				zbzg--
				field, err = dc.ReadMapKeyPtr()
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "SourceIP":
					z.Signature.SourceIP, err = dc.ReadUint32()
					if err != nil {
						return
					}
				case "Port":
					z.Signature.Port, err = dc.ReadUint16()
					if err != nil {
						return
					}
				case "Traffic":
					err = z.Signature.Traffic.DecodeMsg(dc)
					if err != nil {
						return
					}
				default:
					err = dc.Skip()
					if err != nil {
						return
					}
				}
			}
		case "Packets":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Packets = nil
			} else {
				if z.Packets == nil {
					z.Packets = new(EventPackets)
				}
				err = z.Packets.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *Event) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 2
	// write "Signature"
	// map header, size 3
	// write "SourceIP"
	err = en.Append(0x82, 0xa9, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x83, 0xa8, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50)
	if err != nil {
		return err
	}
	err = en.WriteUint32(z.Signature.SourceIP)
	if err != nil {
		return
	}
	// write "Port"
	err = en.Append(0xa4, 0x50, 0x6f, 0x72, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteUint16(z.Signature.Port)
	if err != nil {
		return
	}
	// write "Traffic"
	err = en.Append(0xa7, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63)
	if err != nil {
		return err
	}
	err = z.Signature.Traffic.EncodeMsg(en)
	if err != nil {
		return
	}
	// write "Packets"
	err = en.Append(0xa7, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73)
	if err != nil {
		return err
	}
	if z.Packets == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Packets.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *Event) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "Signature"
	// map header, size 3
	// string "SourceIP"
	o = append(o, 0x82, 0xa9, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x83, 0xa8, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50)
	o = msgp.AppendUint32(o, z.Signature.SourceIP)
	// string "Port"
	o = append(o, 0xa4, 0x50, 0x6f, 0x72, 0x74)
	o = msgp.AppendUint16(o, z.Signature.Port)
	// string "Traffic"
	o = append(o, 0xa7, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63)
	o, err = z.Signature.Traffic.MarshalMsg(o)
	if err != nil {
		return
	}
	// string "Packets"
	o = append(o, 0xa7, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73)
	if z.Packets == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Packets.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Event) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zbai uint32
	zbai, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zbai > 0 {
		zbai--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Signature":
			var zcmr uint32
			zcmr, bts, err = msgp.ReadMapHeaderBytes(bts)
			if err != nil {
				return
			}
			for zcmr > 0 {
				zcmr--
				field, bts, err = msgp.ReadMapKeyZC(bts)
				if err != nil {
					return
				}
				switch msgp.UnsafeString(field) {
				case "SourceIP":
					z.Signature.SourceIP, bts, err = msgp.ReadUint32Bytes(bts)
					if err != nil {
						return
					}
				case "Port":
					z.Signature.Port, bts, err = msgp.ReadUint16Bytes(bts)
					if err != nil {
						return
					}
				case "Traffic":
					bts, err = z.Signature.Traffic.UnmarshalMsg(bts)
					if err != nil {
						return
					}
				default:
					bts, err = msgp.Skip(bts)
					if err != nil {
						return
					}
				}
			}
		case "Packets":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Packets = nil
			} else {
				if z.Packets == nil {
					z.Packets = new(EventPackets)
				}
				bts, err = z.Packets.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *Event) Msgsize() (s int) {
	s = 1 + 10 + 1 + 9 + msgp.Uint32Size + 5 + msgp.Uint16Size + 8 + z.Signature.Traffic.Msgsize() + 8
	if z.Packets == nil {
		s += msgp.NilSize
	} else {
		s += z.Packets.Msgsize()
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventPackets) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zwht uint32
	zwht, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zwht > 0 {
		zwht--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Dests":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Dests = nil
			} else {
				if z.Dests == nil {
					z.Dests = new(set.Uint32Set)
				}
				err = z.Dests.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "First":
			z.First, err = dc.ReadTime()
			if err != nil {
				return
			}
		case "Latest":
			z.Latest, err = dc.ReadTime()
			if err != nil {
				return
			}
		case "Packets":
			z.Packets, err = dc.ReadUint64()
			if err != nil {
				return
			}
		case "Bytes":
			z.Bytes, err = dc.ReadUint64()
			if err != nil {
				return
			}
		case "Samples":
			var zhct uint32
			zhct, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Samples) >= int(zhct) {
				z.Samples = (z.Samples)[:zhct]
			} else {
				z.Samples = make([][]byte, zhct)
			}
			for zajw := range z.Samples {
				z.Samples[zajw], err = dc.ReadBytes(z.Samples[zajw])
				if err != nil {
					return
				}
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *EventPackets) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 6
	// write "Dests"
	err = en.Append(0x86, 0xa5, 0x44, 0x65, 0x73, 0x74, 0x73)
	if err != nil {
		return err
	}
	if z.Dests == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Dests.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "First"
	err = en.Append(0xa5, 0x46, 0x69, 0x72, 0x73, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteTime(z.First)
	if err != nil {
		return
	}
	// write "Latest"
	err = en.Append(0xa6, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteTime(z.Latest)
	if err != nil {
		return
	}
	// write "Packets"
	err = en.Append(0xa7, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteUint64(z.Packets)
	if err != nil {
		return
	}
	// write "Bytes"
	err = en.Append(0xa5, 0x42, 0x79, 0x74, 0x65, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteUint64(z.Bytes)
	if err != nil {
		return
	}
	// write "Samples"
	err = en.Append(0xa7, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x73)
	if err != nil {
		return err
	}
	err = en.WriteArrayHeader(uint32(len(z.Samples)))
	if err != nil {
		return
	}
	for zajw := range z.Samples {
		err = en.WriteBytes(z.Samples[zajw])
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *EventPackets) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 6
	// string "Dests"
	o = append(o, 0x86, 0xa5, 0x44, 0x65, 0x73, 0x74, 0x73)
	if z.Dests == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.Dests.MarshalMsg(o)
		if err != nil {
			return
		}
	}
	// string "First"
	o = append(o, 0xa5, 0x46, 0x69, 0x72, 0x73, 0x74)
	o = msgp.AppendTime(o, z.First)
	// string "Latest"
	o = append(o, 0xa6, 0x4c, 0x61, 0x74, 0x65, 0x73, 0x74)
	o = msgp.AppendTime(o, z.Latest)
	// string "Packets"
	o = append(o, 0xa7, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73)
	o = msgp.AppendUint64(o, z.Packets)
	// string "Bytes"
	o = append(o, 0xa5, 0x42, 0x79, 0x74, 0x65, 0x73)
	o = msgp.AppendUint64(o, z.Bytes)
	// string "Samples"
	o = append(o, 0xa7, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x73)
	o = msgp.AppendArrayHeader(o, uint32(len(z.Samples)))
	for zajw := range z.Samples {
		o = msgp.AppendBytes(o, z.Samples[zajw])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EventPackets) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zcua uint32
	zcua, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zcua > 0 {
		zcua--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Dests":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.Dests = nil
			} else {
				if z.Dests == nil {
					z.Dests = new(set.Uint32Set)
				}
				bts, err = z.Dests.UnmarshalMsg(bts)
				if err != nil {
					return
				}
			}
		case "First":
			z.First, bts, err = msgp.ReadTimeBytes(bts)
			if err != nil {
				return
			}
		case "Latest":
			z.Latest, bts, err = msgp.ReadTimeBytes(bts)
			if err != nil {
				return
			}
		case "Packets":
			z.Packets, bts, err = msgp.ReadUint64Bytes(bts)
			if err != nil {
				return
			}
		case "Bytes":
			z.Bytes, bts, err = msgp.ReadUint64Bytes(bts)
			if err != nil {
				return
			}
		case "Samples":
			var zxhx uint32
			zxhx, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Samples) >= int(zxhx) {
				z.Samples = (z.Samples)[:zxhx]
			} else {
				z.Samples = make([][]byte, zxhx)
			}
			for zajw := range z.Samples {
				z.Samples[zajw], bts, err = msgp.ReadBytesBytes(bts, z.Samples[zajw])
				if err != nil {
					return
				}
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *EventPackets) Msgsize() (s int) {
	s = 1 + 6
	if z.Dests == nil {
		s += msgp.NilSize
	} else {
		s += z.Dests.Msgsize()
	}
	s += 6 + msgp.TimeSize + 7 + msgp.TimeSize + 8 + msgp.Uint64Size + 6 + msgp.Uint64Size + 8 + msgp.ArrayHeaderSize
	for zajw := range z.Samples {
		s += msgp.BytesPrefixSize + len(z.Samples[zajw])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventSignature) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zlqf uint32
	zlqf, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zlqf > 0 {
		zlqf--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "SourceIP":
			z.SourceIP, err = dc.ReadUint32()
			if err != nil {
				return
			}
		case "Port":
			z.Port, err = dc.ReadUint16()
			if err != nil {
				return
			}
		case "Traffic":
			err = z.Traffic.DecodeMsg(dc)
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *EventSignature) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "SourceIP"
	err = en.Append(0x83, 0xa8, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50)
	if err != nil {
		return err
	}
	err = en.WriteUint32(z.SourceIP)
	if err != nil {
		return
	}
	// write "Port"
	err = en.Append(0xa4, 0x50, 0x6f, 0x72, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteUint16(z.Port)
	if err != nil {
		return
	}
	// write "Traffic"
	err = en.Append(0xa7, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63)
	if err != nil {
		return err
	}
	err = z.Traffic.EncodeMsg(en)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *EventSignature) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "SourceIP"
	o = append(o, 0x83, 0xa8, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50)
	o = msgp.AppendUint32(o, z.SourceIP)
	// string "Port"
	o = append(o, 0xa4, 0x50, 0x6f, 0x72, 0x74)
	o = msgp.AppendUint16(o, z.Port)
	// string "Traffic"
	o = append(o, 0xa7, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63)
	o, err = z.Traffic.MarshalMsg(o)
	if err != nil {
		return
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EventSignature) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zdaf uint32
	zdaf, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zdaf > 0 {
		zdaf--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "SourceIP":
			z.SourceIP, bts, err = msgp.ReadUint32Bytes(bts)
			if err != nil {
				return
			}
		case "Port":
			z.Port, bts, err = msgp.ReadUint16Bytes(bts)
			if err != nil {
				return
			}
		case "Traffic":
			bts, err = z.Traffic.UnmarshalMsg(bts)
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *EventSignature) Msgsize() (s int) {
	s = 1 + 9 + msgp.Uint32Size + 5 + msgp.Uint16Size + 8 + z.Traffic.Msgsize()
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventSignatureIPv6) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zjfb uint32
	zjfb, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zjfb > 0 {
		zjfb--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "SourceIPv6":
			err = dc.ReadExactBytes((z.SourceIPv6)[:])
			if err != nil {
				return
			}
		case "Port":
			z.Port, err = dc.ReadUint16()
			if err != nil {
				return
			}
		case "Traffic":
			err = z.Traffic.DecodeMsg(dc)
			if err != nil {
				return
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *EventSignatureIPv6) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "SourceIPv6"
	err = en.Append(0x83, 0xaa, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50, 0x76, 0x36)
	if err != nil {
		return err
	}
	err = en.WriteBytes((z.SourceIPv6)[:])
	if err != nil {
		return
	}
	// write "Port"
	err = en.Append(0xa4, 0x50, 0x6f, 0x72, 0x74)
	if err != nil {
		return err
	}
	err = en.WriteUint16(z.Port)
	if err != nil {
		return
	}
	// write "Traffic"
	err = en.Append(0xa7, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63)
	if err != nil {
		return err
	}
	err = z.Traffic.EncodeMsg(en)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *EventSignatureIPv6) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "SourceIPv6"
	o = append(o, 0x83, 0xaa, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50, 0x76, 0x36)
	o = msgp.AppendBytes(o, (z.SourceIPv6)[:])
	// string "Port"
	o = append(o, 0xa4, 0x50, 0x6f, 0x72, 0x74)
	o = msgp.AppendUint16(o, z.Port)
	// string "Traffic"
	o = append(o, 0xa7, 0x54, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63)
	o, err = z.Traffic.MarshalMsg(o)
	if err != nil {
		return
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EventSignatureIPv6) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zcxo uint32
	zcxo, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zcxo > 0 {
		zcxo--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "SourceIPv6":
			bts, err = msgp.ReadExactBytes(bts, (z.SourceIPv6)[:])
			if err != nil {
				return
			}
		case "Port":
			z.Port, bts, err = msgp.ReadUint16Bytes(bts)
			if err != nil {
				return
			}
		case "Traffic":
			bts, err = z.Traffic.UnmarshalMsg(bts)
			if err != nil {
				return
			}
		default:
			bts, err = msgp.Skip(bts)
			if err != nil {
				return
			}
		}
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *EventSignatureIPv6) Msgsize() (s int) {
	s = 1 + 11 + msgp.ArrayHeaderSize + (16 * (msgp.ByteSize)) + 5 + msgp.Uint16Size + 8 + z.Traffic.Msgsize()
	return
}
