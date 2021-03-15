package set

import (
	"github.com/tinylib/msgp/msgp"
)

type IPSet struct {
	M map[[16]byte]struct{}
}

// NewIPSet initialises a new Set.
func NewIPSet() *IPSet {
	s := new(IPSet)
	s.M = make(map[[16]byte]struct{})
	return s
}

// Add adds an item to a Set. If the item is already present, it will not be
// re-added.
func (s *IPSet) Add(k [16]byte) {
	if _, found := s.M[k]; found == true {
		return
	}
	var none struct{}
	s.M[k] = none
}

// Size returns the amount of items in the set.
func (s *IPSet) Size() int {
	return len(s.M)
}

// ByteSize approximates the number of bytes taken up by the object.
func (s *IPSet) ByteSize() int {
	return len(s.M) * 16
}

// Contains returns true if the item is already in the set.
func (s *IPSet) Contains(item [16]byte) bool {
	if _, found := s.M[item]; found == true {
		return true
	}
	return false
}

// Map returns the underlying data structure of the set.
func (s *IPSet) Map() *map[[16]byte]struct{} {
	return &s.M
}

// DecodeMsg implements msgp.Decodable
func (s *IPSet) DecodeMsg(dc *msgp.Reader) (err error) {
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
				s.M = make(map[[16]byte]struct {
				}, zb0002)
			} else if len(s.M) > 0 {
				for key := range s.M {
					delete(s.M, key)
				}
			}
			for zb0002 > 0 {
				zb0002--
				var za0001 []byte
				err = dc.ReadExactBytes(za0001)
				if err != nil {
					err = msgp.WrapError(err, "M")
					return
				}
				var za0002 struct{}
				var key [16]byte
				copy(key[:], za0001)
				s.M[key] = za0002
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
func (s *IPSet) EncodeMsg(en *msgp.Writer) (err error) {
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
		var bytes []byte
		for _, j := range za0001 {
			bytes = append(bytes, j)
		}
		err = en.WriteBytes(bytes)
		if err != nil {
			err = msgp.WrapError(err, "M")
			return
		}
	}
	return
}

// MarshalMsg implements msgp.Marshaler
func (s *IPSet) MarshalMsg(b []byte) (o []byte, err error) {
	panic("NOT IMPLEMENTED.")
}

// UnmarshalMsg implements msgp.Unmarshaler
func (s *IPSet) UnmarshalMsg(bts []byte) (o []byte, err error) {
	panic("NOT IMPLEMENTED.")
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (s *IPSet) Msgsize() (z int) {
	panic("NOT IMPLEMENTED.")
}

