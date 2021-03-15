package cache

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *Cache) DecodeMsg(dc *msgp.Reader) (err error) {
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
		case "Cleared":
			z.Cleared, err = dc.ReadTime()
			if err != nil {
				return
			}
		case "First":
			z.First, err = dc.ReadTime()
			if err != nil {
				return
			}
		case "Now":
			z.Now, err = dc.ReadTime()
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
func (z Cache) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 3
	// write "Cleared"
	err = en.Append(0x83, 0xa7, 0x43, 0x6c, 0x65, 0x61, 0x72, 0x65, 0x64)
	if err != nil {
		return err
	}
	err = en.WriteTime(z.Cleared)
	if err != nil {
		return
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
	// write "Now"
	err = en.Append(0xa3, 0x4e, 0x6f, 0x77)
	if err != nil {
		return err
	}
	err = en.WriteTime(z.Now)
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z Cache) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	// map header, size 3
	// string "Cleared"
	o = append(o, 0x83, 0xa7, 0x43, 0x6c, 0x65, 0x61, 0x72, 0x65, 0x64)
	o = msgp.AppendTime(o, z.Cleared)
	// string "First"
	o = append(o, 0xa5, 0x46, 0x69, 0x72, 0x73, 0x74)
	o = msgp.AppendTime(o, z.First)
	// string "Now"
	o = append(o, 0xa3, 0x4e, 0x6f, 0x77)
	o = msgp.AppendTime(o, z.Now)
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *Cache) UnmarshalMsg(bts []byte) (o []byte, err error) {
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
		case "Cleared":
			z.Cleared, bts, err = msgp.ReadTimeBytes(bts)
			if err != nil {
				return
			}
		case "First":
			z.First, bts, err = msgp.ReadTimeBytes(bts)
			if err != nil {
				return
			}
		case "Now":
			z.Now, bts, err = msgp.ReadTimeBytes(bts)
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
func (z Cache) Msgsize() (s int) {
	s = 1 + 8 + msgp.TimeSize + 6 + msgp.TimeSize + 4 + msgp.TimeSize
	return
}
