package internal

type randSource struct {
	state uint64
}

func newSource(seed uint64) (r *randSource) {
	if seed == 0 {
		seed = 8732932
	}
	r = new(randSource)
	r.state = seed
	return r
}

func (r *randSource) randInt64() int64 {
	r.state = r.state ^ (r.state >> 12)
	r.state = r.state ^ (r.state << 25)
	r.state = r.state ^ (r.state >> 27)
	return int64(r.state * 0x2545F4914F6CDD1D)
}
