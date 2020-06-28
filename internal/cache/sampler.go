package cache

import (
	"math/rand"
	"time"
)

// Sampler is a data structure designed to
//
// Note: Some of Sampler's members are exported due to gob's inability to gob
// unexported members. These members should nevertheless not be directly
// accessed outside of this package.
//
// TODO: randSource and randGenerator are unexported because they don't play
// nice with gob. In the future, these should somehow be saved to avoid
// reinitialisation.
type Sampler struct {
	NumSamples     int
	RandSourceTime int64
	randSource     rand.Source
	randGenerator  *rand.Rand
}

// newSampler creates a new sampler object and returns a pointer to it.
func newSampler(numSamples int) *Sampler {
	s := new(Sampler)
	s.NumSamples = numSamples
	s.RandSourceTime = time.Now().UnixNano()
	s.randSource = rand.NewSource(s.RandSourceTime)
	s.randGenerator = rand.New(s.randSource)
	return s
}

// reinitSampler reinitialises the random generator for the given Sampler. This
// should be done if the Sampler is being loaded from a souce file via gob.
func (s *Sampler) reinitSampler() {
	s.randSource = rand.NewSource(s.RandSourceTime)
	s.randGenerator = rand.New(s.randSource)
}

// sample returns an index into the sample array that the object (of index i)
// should be placed at, or -1 if the object should not be sampled.
func (s *Sampler) sample(i int) int {
	// If this is within the first NumSamples samples, we must choose it.

	if i < s.NumSamples {
		return i
	}

	// Determine if the object at i should be sampled. If so, return the index
	// it should be placed at.
	random := s.randGenerator.Intn(i + 1)
	if random < s.NumSamples {
		return random
	}

	return -1
}
