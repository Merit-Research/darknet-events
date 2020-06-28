package set

import (
	"github.com/tinylib/msgp/msgp"
)

// Uint32Set is a set that holds uint32s.
//
// NOTE: M is exported for msgp's sake but should not be used outside of this
// package.
type Uint32Set struct {
	M map[uint32]struct{}
}

// NewUint32Set initialises a new Set.
func NewUint32Set() *Uint32Set {
	s := new(Uint32Set)
	s.M = make(map[uint32]struct{})
	return s
}

// Add adds an item to a Set. If the item is already present, it will not be
// re-added.
func (s *Uint32Set) Add(k uint32) {
	if _, found := s.M[k]; found == true {
		return
	}
	var none struct{}
	s.M[k] = none
}

// Size returns the amount of items in the set.
func (s *Uint32Set) Size() int {
	return len(s.M)
}

// ByteSize approximates the number of bytes taken up by the object.
func (s *Uint32Set) ByteSize() int {
	return len(s.M) * 4
}

// Contains returns true if the item is already in the set.
func (s *Uint32Set) Contains(item uint32) bool {
	if _, found := s.M[item]; found == true {
		return true
	}
	return false
}

// Map returns the underlying data structure of the set.
func (s *Uint32Set) Map() *map[uint32]struct{} {
	return &s.M
}

// DecodeMsg implements msgp.Decodable
func (s *Uint32Set) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zb0001 uint32
	zb0001, err = dc.ReadMapHeader()
	if err != nil {
		err = msgp.WrapError(err)
		return
	}
	for zb0001 > 0 {
		zb0001--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			err = msgp.WrapError(err)
			return
		}
		switch msgp.UnsafeString(field) {
		case "M":
			var zb0002 uint32
			zb0002, err = dc.ReadMapHeader()
			if err != nil {
				err = msgp.WrapError(err, "M")
				return
			}
			if s.M == nil {
				s.M = make(map[uint32]struct {
				}, zb0002)
			} else if len(s.M) > 0 {
				for key := range s.M {
					delete(s.M, key)
				}
			}
			for zb0002 > 0 {
				zb0002--
				var za0001 uint32
				za0001, err = dc.ReadUint32()
				if err != nil {
					err = msgp.WrapError(err, "M")
					return
				}
				var za0002 struct{}
				s.M[za0001] = za0002
			}
		default:
			err = dc.Skip()
			if err != nil {
				err = msgp.WrapError(err)
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (s *Uint32Set) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 1
	// write "M"
	err = en.Append(0x81, 0xa1, 0x4d)
	if err != nil {
		return
	}
	err = en.WriteMapHeader(uint32(len(s.M)))
	if err != nil {
		err = msgp.WrapError(err, "M")
		return
	}
	for za0001 := range s.M {
		err = en.WriteUint32(za0001)
		if err != nil {
			err = msgp.WrapError(err, "M")
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (s *Uint32Set) MarshalMsg(b []byte) (o []byte, err error) {
	panic("NOT IMPLEMENTED.")
}

// UnmarshalMsg implements msgp.Unmarshaler
func (s *Uint32Set) UnmarshalMsg(bts []byte) (o []byte, err error) {
	panic("NOT IMPLEMENTED.")
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (s *Uint32Set) Msgsize() (z int) {
	panic("NOT IMPLEMENTED.")
}
