package internal

import (
	"reflect"
	"testing"
)

func TestMakeKey(t *testing.T) {
	cases := []struct {
		passphrase []byte
		key        [32]byte
	}{
		{
			[]byte("The quick brown fox jumps over the lazy dog"),
			[32]byte{15, 48, 157, 126, 226, 161, 177, 126, 96, 8, 153, 41, 232, 67, 173, 153, 192, 34, 172, 63, 175, 127, 83, 127, 197, 110, 184, 239, 234, 195, 168, 183},
		},
		{
			[]byte("Short"),
			[32]byte{58, 152, 92, 33, 236, 187, 16, 118, 168, 218, 112, 48, 40, 220, 86, 101, 43, 16, 40, 116, 248, 152, 135, 226, 103, 134, 161, 32, 161, 90, 156, 227},
		},
	}
	for _, c := range cases {
		out := MakeKey(&c.passphrase)
		if !reflect.DeepEqual(*out, c.key) {
			t.Errorf("MakeKey(%v) == %v want %v", c.passphrase, *out, c.key)
		}
	}
}
