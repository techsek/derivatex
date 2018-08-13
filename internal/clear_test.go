package internal

import (
	"reflect"
	"testing"
)

func Test_clearAndTrim(t *testing.T) {
	cases := []struct {
		secretBytes        []byte
		n                  int
		trimmedSecretBytes []byte
	}{
		{
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			-1,
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			0,
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		},
		{
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			3,
			[]byte{3, 4, 5, 6, 7, 8, 9},
		},
		{
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			10,
			[]byte{},
		},
		{
			[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			15,
			[]byte{},
		},
	}
	for _, c := range cases {
		clearAndTrim(&c.secretBytes, c.n)
		if !reflect.DeepEqual(c.secretBytes, c.trimmedSecretBytes) {
			t.Errorf("clearAndTrim(&c.secretBytes, %d) == %v want %v", c.n, c.secretBytes, c.trimmedSecretBytes)
		}
	}
}
