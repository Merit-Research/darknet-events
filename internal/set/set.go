package set

// Set is a simple abstraction layer over the Go map type to make it more
// useful as a pure set type. Set uses an empty struct as the value type to
// minimise the amount of unnecessary memory allocated.
type Set interface {
	Add(item interface{})
	Size() int
	ByteSize() int
	Contains(item interface{}) bool
}
