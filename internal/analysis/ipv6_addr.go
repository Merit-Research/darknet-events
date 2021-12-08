package analysis

import (
	"github.com/tinylib/msgp/msgp"
)

type IPv6Addr [16]byte

func init() {
	msgp.RegisterExtension(99, func() msgp.Extension { return new(IPv6Addr) })
	msgp.RegisterExtension(100, func() msgp.Extension { return new(IPv6AddrSet) })
}

func (a *IPv6Addr) ExtensionType() int8 {
	return 99
}

func (a *IPv6Addr) Len() int {
	return 16
}

func (a *IPv6Addr) MarshalBinaryTo(b []byte) error {
	copy(b, (*a)[:])
	return nil
}

func (a *IPv6Addr) UnmarshalBinary(b []byte) error {
	copy((*a)[:], b)
	return nil
}

type IPv6AddrSet struct {
	M []IPv6Addr
}

func (a *IPv6AddrSet) ExtensionType() int8 {
	return 100
}

func (a *IPv6AddrSet) Len() int {
	return len(a.M) * 16
}

func (a *IPv6AddrSet) MarshalBinaryTo(b []byte) error {
	var size = a.Size()

	for i := 0; i < size; i++ {
		for j := 0; j < 16; j++ {
			b = append(b, a.M[i][j])
		}
	}

	return nil
}

func (a *IPv6AddrSet) UnmarshalBinary(b []byte) error {
	b_len := len(b)

	for i := 0; i < b_len/16; i++ {
		var to_add = new(IPv6Addr)
		copy(to_add[:], b[i*16:i*16+16])
		a.Add(*to_add)
	}

	return nil
}

func (a *IPv6AddrSet) Add(addr IPv6Addr) {
	for _, val := range a.M {
		if addr == val {
			return
		}
	}

	a.M = append(a.M, addr)
}

func (a *IPv6AddrSet) Size() int {
	return len(a.M)
}

func (a *IPv6AddrSet) Dest64s() *IPv6AddrSet {
	var ret = new(IPv6AddrSet)
	for _, val := range a.M {
		var x = new(IPv6Addr)
		copy(x[:], val[:])
		for i := 8; i < 16; i++ {
			x[i] = 0
		}
		ret.Add(*x)
	}
	return ret
}
