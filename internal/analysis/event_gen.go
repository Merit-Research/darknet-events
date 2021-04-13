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
		case "Source":
			err = z.Source.DecodeMsg(dc)
			if err != nil {
				return
			}
		case "Packets":
			err = z.Packets.DecodeMsg(dc)
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
func (z *Event) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 2
	// write "Source"
	err = en.Append(0x82, 0xa6, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65)
	if err != nil {
		return err
	}
	err = z.Source.EncodeMsg(en)
	if err != nil {
		return
	}
	// write "Packets"
	err = en.Append(0xa7, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73)
	if err != nil {
		return err
	}
	err = z.Packets.EncodeMsg(en)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *Event) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 2
	// string "Source"
	o = append(o, 0x82, 0xa6, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65)
	o, err = z.Source.MarshalMsg(o)
	if err != nil {
		return
	}
	// string "Packets"
	o = append(o, 0xa7, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73)
	o, err = z.Packets.MarshalMsg(o)
	if err != nil {
		return
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Event) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zbzg uint32
	zbzg, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zbzg > 0 {
		zbzg--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Source":
			bts, err = z.Source.UnmarshalMsg(bts)
			if err != nil {
				return
			}
		case "Packets":
			bts, err = z.Packets.UnmarshalMsg(bts)
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
func (z *Event) Msgsize() (s int) {
	s = 1 + 7 + z.Source.Msgsize() + 8 + z.Packets.Msgsize()
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventPacketsIPv4) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zcmr uint32
	zcmr, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zcmr > 0 {
		zcmr--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "DestIPv4":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.DestIPv4 = nil
			} else {
				if z.DestIPv4 == nil {
					z.DestIPv4 = new(set.Uint32Set)
				}
				err = z.DestIPv4.DecodeMsg(dc)
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
			var zajw uint32
			zajw, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Samples) >= int(zajw) {
				z.Samples = (z.Samples)[:zajw]
			} else {
				z.Samples = make([][]byte, zajw)
			}
			for zbai := range z.Samples {
				z.Samples[zbai], err = dc.ReadBytes(z.Samples[zbai])
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
func (z *EventPacketsIPv4) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 6
	// write "DestIPv4"
	err = en.Append(0x86, 0xa8, 0x44, 0x65, 0x73, 0x74, 0x49, 0x50, 0x76, 0x34)
	if err != nil {
		return err
	}
	if z.DestIPv4 == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.DestIPv4.EncodeMsg(en)
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
	for zbai := range z.Samples {
		err = en.WriteBytes(z.Samples[zbai])
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *EventPacketsIPv4) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 6
	// string "DestIPv4"
	o = append(o, 0x86, 0xa8, 0x44, 0x65, 0x73, 0x74, 0x49, 0x50, 0x76, 0x34)
	if z.DestIPv4 == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.DestIPv4.MarshalMsg(o)
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
	for zbai := range z.Samples {
		o = msgp.AppendBytes(o, z.Samples[zbai])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EventPacketsIPv4) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zwht uint32
	zwht, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zwht > 0 {
		zwht--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "DestIPv4":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.DestIPv4 = nil
			} else {
				if z.DestIPv4 == nil {
					z.DestIPv4 = new(set.Uint32Set)
				}
				bts, err = z.DestIPv4.UnmarshalMsg(bts)
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
			var zhct uint32
			zhct, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Samples) >= int(zhct) {
				z.Samples = (z.Samples)[:zhct]
			} else {
				z.Samples = make([][]byte, zhct)
			}
			for zbai := range z.Samples {
				z.Samples[zbai], bts, err = msgp.ReadBytesBytes(bts, z.Samples[zbai])
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
func (z *EventPacketsIPv4) Msgsize() (s int) {
	s = 1 + 9
	if z.DestIPv4 == nil {
		s += msgp.NilSize
	} else {
		s += z.DestIPv4.Msgsize()
	}
	s += 6 + msgp.TimeSize + 7 + msgp.TimeSize + 8 + msgp.Uint64Size + 6 + msgp.Uint64Size + 8 + msgp.ArrayHeaderSize
	for zbai := range z.Samples {
		s += msgp.BytesPrefixSize + len(z.Samples[zbai])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventPacketsIPv6) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zxhx uint32
	zxhx, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zxhx > 0 {
		zxhx--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "DestIPv6":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.DestIPv6 = nil
			} else {
				if z.DestIPv6 == nil {
					z.DestIPv6 = new(set.IPSet)
				}
				err = z.DestIPv6.DecodeMsg(dc)
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
			var zlqf uint32
			zlqf, err = dc.ReadArrayHeader()
			if err != nil {
				return
			}
			if cap(z.Samples) >= int(zlqf) {
				z.Samples = (z.Samples)[:zlqf]
			} else {
				z.Samples = make([][]byte, zlqf)
			}
			for zcua := range z.Samples {
				z.Samples[zcua], err = dc.ReadBytes(z.Samples[zcua])
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
func (z *EventPacketsIPv6) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 6
	// write "DestIPv6"
	err = en.Append(0x86, 0xa8, 0x44, 0x65, 0x73, 0x74, 0x49, 0x50, 0x76, 0x36)
	if err != nil {
		return err
	}
	if z.DestIPv6 == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.DestIPv6.EncodeMsg(en)
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
	for zcua := range z.Samples {
		err = en.WriteBytes(z.Samples[zcua])
		if err != nil {
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z *EventPacketsIPv6) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 6
	// string "DestIPv6"
	o = append(o, 0x86, 0xa8, 0x44, 0x65, 0x73, 0x74, 0x49, 0x50, 0x76, 0x36)
	if z.DestIPv6 == nil {
		o = msgp.AppendNil(o)
	} else {
		o, err = z.DestIPv6.MarshalMsg(o)
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
	for zcua := range z.Samples {
		o = msgp.AppendBytes(o, z.Samples[zcua])
	}
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *EventPacketsIPv6) UnmarshalMsg(bts []byte) (o []byte, err error) {
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
		case "DestIPv6":
			if msgp.IsNil(bts) {
				bts, err = msgp.ReadNilBytes(bts)
				if err != nil {
					return
				}
				z.DestIPv6 = nil
			} else {
				if z.DestIPv6 == nil {
					z.DestIPv6 = new(set.IPSet)
				}
				bts, err = z.DestIPv6.UnmarshalMsg(bts)
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
			var zpks uint32
			zpks, bts, err = msgp.ReadArrayHeaderBytes(bts)
			if err != nil {
				return
			}
			if cap(z.Samples) >= int(zpks) {
				z.Samples = (z.Samples)[:zpks]
			} else {
				z.Samples = make([][]byte, zpks)
			}
			for zcua := range z.Samples {
				z.Samples[zcua], bts, err = msgp.ReadBytesBytes(bts, z.Samples[zcua])
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
func (z *EventPacketsIPv6) Msgsize() (s int) {
	s = 1 + 9
	if z.DestIPv6 == nil {
		s += msgp.NilSize
	} else {
		s += z.DestIPv6.Msgsize()
	}
	s += 6 + msgp.TimeSize + 7 + msgp.TimeSize + 8 + msgp.Uint64Size + 6 + msgp.Uint64Size + 8 + msgp.ArrayHeaderSize
	for zcua := range z.Samples {
		s += msgp.BytesPrefixSize + len(z.Samples[zcua])
	}
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventSignatureIPv4) DecodeMsg(dc *msgp.Reader) (err error) {
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
		case "SourceIPv4":
			z.SourceIPv4, err = dc.ReadUint32()
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
func (z *EventSignatureIPv4) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "SourceIPv4"
	err = en.Append(0x83, 0xaa, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50, 0x76, 0x34)
	if err != nil {
		return err
	}
	err = en.WriteUint32(z.SourceIPv4)
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
func (z *EventSignatureIPv4) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "SourceIPv4"
	o = append(o, 0x83, 0xaa, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50, 0x76, 0x34)
	o = msgp.AppendUint32(o, z.SourceIPv4)
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
func (z *EventSignatureIPv4) UnmarshalMsg(bts []byte) (o []byte, err error) {
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
		case "SourceIPv4":
			z.SourceIPv4, bts, err = msgp.ReadUint32Bytes(bts)
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
func (z *EventSignatureIPv4) Msgsize() (s int) {
	s = 1 + 11 + msgp.Uint32Size + 5 + msgp.Uint16Size + 8 + z.Traffic.Msgsize()
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventSignatureIPv6) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zrsw uint32
	zrsw, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zrsw > 0 {
		zrsw--
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
	var zxpk uint32
	zxpk, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zxpk > 0 {
		zxpk--
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

// DecodeMsg implements msgp.Decodable
func (z *EventSourceIPv4) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zdnj uint32
	zdnj, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zdnj > 0 {
		zdnj--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "SourceIPv4":
			z.SourceIPv4, err = dc.ReadUint32()
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
func (z *EventSourceIPv4) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "SourceIPv4"
	err = en.Append(0x83, 0xaa, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50, 0x76, 0x34)
	if err != nil {
		return err
	}
	err = en.WriteUint32(z.SourceIPv4)
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
func (z *EventSourceIPv4) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "SourceIPv4"
	o = append(o, 0x83, 0xaa, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x49, 0x50, 0x76, 0x34)
	o = msgp.AppendUint32(o, z.SourceIPv4)
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
func (z *EventSourceIPv4) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zobc uint32
	zobc, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zobc > 0 {
		zobc--
		field, bts, err = msgp.ReadMapKeyZC(bts)
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "SourceIPv4":
			z.SourceIPv4, bts, err = msgp.ReadUint32Bytes(bts)
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
func (z *EventSourceIPv4) Msgsize() (s int) {
	s = 1 + 11 + msgp.Uint32Size + 5 + msgp.Uint16Size + 8 + z.Traffic.Msgsize()
	return
}

// DecodeMsg implements msgp.Decodable
func (z *EventSourceIPv6) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zkgt uint32
	zkgt, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zkgt > 0 {
		zkgt--
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
func (z *EventSourceIPv6) EncodeMsg(en *msgp.Writer) (err error) {
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
func (z *EventSourceIPv6) MarshalMsg(b []byte) (o []byte, err error) {
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
func (z *EventSourceIPv6) UnmarshalMsg(bts []byte) (o []byte, err error) {
	var field []byte
	_ = field
	var zema uint32
	zema, bts, err = msgp.ReadMapHeaderBytes(bts)
	if err != nil {
		return
	}
	for zema > 0 {
		zema--
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
func (z *EventSourceIPv6) Msgsize() (s int) {
	s = 1 + 11 + msgp.ArrayHeaderSize + (16 * (msgp.ByteSize)) + 5 + msgp.Uint16Size + 8 + z.Traffic.Msgsize()
	return
}
