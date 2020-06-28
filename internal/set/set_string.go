package set

import (
	"unsafe"
)

// StringSet is a set that holds strings.
//
// NOTE: M is exported for msgp's sake but should not be used outside of this
// package.
type StringSet struct {
	M map[string]struct{}
}

// NewStringSet initialises a new Set.
func NewStringSet() *StringSet {
	s := new(StringSet)
	s.M = make(map[string]struct{})
	return s
}

// Add adds an item to a Set. If the item is already present, it will not be
// re-added.
func (s *StringSet) Add(k string) {
	if _, found := s.M[k]; found == true {
		return
	}
	var noMem struct{}
	s.M[k] = noMem
}

// Size returns the amount of items in the set.
func (s *StringSet) Size() int {
	return len(s.M)
}

// ByteSize approximates the number of bytes taken up by the object.
func (s *StringSet) ByteSize() int {
	size := 0
	for k := range s.M {
		size += int(unsafe.Sizeof(k))
		size += len(k)
	}
	return size
}

// Contains returns true if the item is already in the set.
func (s *StringSet) Contains(item string) bool {
	if _, found := s.M[item]; found == true {
		return true
	}
	return false
}

// Map returns the underlying data structure of the set.
func (s *StringSet) Map() *map[string]struct{} {
	return &s.M
}
