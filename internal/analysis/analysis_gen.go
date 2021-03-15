package analysis

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *TrafficType) DecodeMsg(dc *msgp.Reader) (err error) {
	{
		var zxvk uint16
		zxvk, err = dc.ReadUint16()
		(*z) = TrafficType(zxvk)
	}
	if err != nil {
		return
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z TrafficType) EncodeMsg(en *msgp.Writer) (err error) {
	err = en.WriteUint16(uint16(z))
	if err != nil {
		return
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (z TrafficType) MarshalMsg(b []byte) (o []byte, err error) {
	o = msgp.Require(b, z.Msgsize())
	o = msgp.AppendUint16(o, uint16(z))
	return
}

// UnmarshalMsg implements msgp.Unmarshaler
func (z *TrafficType) UnmarshalMsg(bts []byte) (o []byte, err error) {
	{
		var zbzg uint16
		zbzg, bts, err = msgp.ReadUint16Bytes(bts)
		(*z) = TrafficType(zbzg)
	}
	if err != nil {
		return
	}
	o = bts
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z TrafficType) Msgsize() (s int) {
	s = msgp.Uint16Size
	return
}
