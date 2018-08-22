package internal

import (
	"testing"
)

func Test_randInt64(t *testing.T) {
	cases := []struct {
		seed    uint64
		rounds  int
		integer int64
	}{
		{
			1,
			1,
			5180492295206395165,
		},
		{
			1,
			2,
			6066446928794000099,
		},
		{
			2,
			2,
			6313850216121551418,
		},
	}
	for _, c := range cases {
		r := newSource(c.seed)
		var out int64
		for c.rounds > 0 {
			out = r.randInt64()
			c.rounds--
		}
		if out != c.integer {
			t.Errorf("%v.randInt64() == %d want %d", r, out, c.integer)
		}
	}
}
