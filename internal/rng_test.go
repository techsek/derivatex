package internal

import (
	"testing"
)

func Test_randInt64(t *testing.T) {
	cases := []struct {
		r       randSource
		rounds  int
		integer int64
	}{
		{
			randSource{1},
			1,
			5180492295206395165,
		},
		{
			randSource{1},
			2,
			-6066446928794000099,
		},
		{
			randSource{2},
			2,
			6313850216121551418,
		},
	}
	for _, c := range cases {
		var out int64
		for i := 0; i < c.rounds; i++ {
			out = c.r.randInt64()
		}
		if out != c.integer {
			t.Errorf("%v.randInt64() == %d want %d", c.r, out, c.integer)
		}
	}
}
