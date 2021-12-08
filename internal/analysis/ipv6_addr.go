package analysis

import "github.com/tinylib/msgp/msgp"

type IPv6Addr [16]byte

func init() {
	msgp.RegisterExtension(99, func() msgp.Extension { return new(IPv6Addr) })
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

func (a *IPv6Addr) Size() int {
	return 16
}
