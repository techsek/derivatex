package internal

import (
	"errors"
	"reflect"
	"testing"
)

func Test_chechsumize(t *testing.T) {
	cases := []struct {
		data         []byte
		checksumData []byte
	}{
		{
			[]byte{215, 168, 251, 179, 7, 215, 128, 148},
			[]byte{215, 168, 251, 179, 7, 215, 128, 148, 9, 214, 139, 100},
		},
		{
			[]byte{},
			[]byte{167, 255, 198, 248},
		},
	}
	for _, c := range cases {
		out := c.data
		Checksumize(&out)
		if !reflect.DeepEqual(out, c.checksumData) {
			t.Errorf("Checksumize(%v) == %v want %v", c.data, out, c.checksumData)
		}
	}
}

func Test_dechechsumize(t *testing.T) {
	cases := []struct {
		checksumData []byte
		data         []byte
		err          error
	}{
		{
			[]byte{215, 168, 251, 179, 7, 215, 128, 148, 9, 214, 139, 100},
			[]byte{215, 168, 251, 179, 7, 215, 128, 148},
			nil,
		},
		{
			[]byte{167, 255, 198, 248},
			[]byte{},
			nil,
		},
		{
			[]byte{216, 168, 251, 179, 7, 215, 128, 148, 9, 214, 139, 100},
			nil,
			errors.New("Checksum verification failed"),
		},
		{
			[]byte{167, 255, 198},
			nil,
			errors.New("Checksumed data is not long enough to contain the checksum"),
		},
		{
			[]byte{},
			nil,
			errors.New("Checksumed data is not long enough to contain the checksum"),
		},
	}
	for _, c := range cases {
		out := c.checksumData
		err := Dechecksumize(&out)
		equal, m := errorsEqual(err, c.err)
		if !equal {
			t.Errorf("Dechecksumize(%v) - %s", c.checksumData, m)
		}
		if err == nil && !reflect.DeepEqual(out, c.data) {
			t.Errorf("dechecksumize(%v) == %v want %v", c.checksumData, out, c.data)
		}
	}
}
