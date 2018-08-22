package internal

import (
	"fmt"
	"strconv"
)

type randSource struct {
	state uint64
}

func newSource(seed uint64) (r *randSource) {
	if seed == 0 {
		seed = 8732932 // very unlikely to happen
	}
	r = new(randSource)
	r.state = seed
	return r
}

// Returns a non-negative int64 value
func (r *randSource) randInt64() (v int64) {
	r.state = r.state ^ (r.state >> 12)
	r.state = r.state ^ (r.state << 25)
	r.state = r.state ^ (r.state >> 27)
	v = int64(r.state * 0x2545F4914F6CDD1D)
	if v < 0 {
		v = -v
	}
	return v
}

func (r *randSource) String() string {
	return fmt.Sprintf("randSource(state=" + strconv.FormatUint(r.state, 10) + ")")
}
