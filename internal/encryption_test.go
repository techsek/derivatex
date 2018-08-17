package internal

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestEncryptAES(t *testing.T) {
	cases := []struct {
		ioReadFull func(reader io.Reader, iv []byte) (n int, err error)
		plaintext  []byte
		key        [32]byte
		ciphertext []byte
		err        error
	}{
		{
			func(reader io.Reader, iv []byte) (n int, err error) { return 0, nil },
			[]byte("The quick brown fox jumps over the lazy dog"),
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 236, 46, 33, 228, 130, 243, 229, 203, 165, 49, 78, 56, 28, 74, 207, 254, 228, 161, 17, 81, 92, 146, 77, 123, 239, 121, 141, 46, 80, 80, 238, 75, 168, 97, 24, 89, 126, 108, 68, 116, 82, 199, 114},
			nil,
		},
		{
			func(reader io.Reader, iv []byte) (n int, err error) { return 0, nil },
			[]byte("Short"),
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 235, 46, 43, 182, 135},
			nil,
		},
		{
			func(reader io.Reader, iv []byte) (n int, err error) { return 0, errors.New("unexpected EOF") },
			[]byte("The quick brown fox jumps over the lazy dog"),
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			nil,
			errors.New("unexpected EOF"),
		},
	}
	for _, c := range cases {
		out, err := EncryptAES(&c.plaintext, &c.key, c.ioReadFull)
		equal, m := errorsEqual(err, c.err)
		if !equal {
			t.Errorf("encryptAES(%v, %v) - %s", c.plaintext, c.key, m)
		}
		if err == nil && !reflect.DeepEqual(*out, c.ciphertext) {
			t.Errorf("encryptAES(%v, %v) == %v want %v", c.plaintext, c.key, *out, c.ciphertext)
		}
	}
}

func TestDecryptAES(t *testing.T) {
	cases := []struct {
		ciphertext []byte
		key        [32]byte
		plaintext  []byte
		err        error
	}{
		{
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 236, 46, 33, 228, 130, 243, 229, 203, 165, 49, 78, 56, 28, 74, 207, 254, 228, 161, 17, 81, 92, 146, 77, 123, 239, 121, 141, 46, 80, 80, 238, 75, 168, 97, 24, 89, 126, 108, 68, 116, 82, 199, 114},
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			[]byte("The quick brown fox jumps over the lazy dog"),
			nil,
		},
		{
			[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 235, 46, 43, 182, 135},
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			[]byte("Short"),
			nil,
		},
	}
	for _, c := range cases {
		out, err := DecryptAES(&c.ciphertext, &c.key)
		equal, m := errorsEqual(err, c.err)
		if !equal {
			t.Errorf("decryptAES(%v, %v) - %s", c.ciphertext, c.key, m)
		}
		if err == nil && !reflect.DeepEqual(*out, c.plaintext) {
			t.Errorf("decryptAES(%v, %v) == %v want %v", c.ciphertext, c.key, *out, c.plaintext)
		}
	}
}

func TestEncryptDecryptAES(t *testing.T) {
	cases := []struct {
		plaintext []byte
		key       [32]byte
		err       error
	}{
		{
			[]byte("The quick brown fox jumps over the lazy dog"),
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			nil,
		},
		{
			[]byte("Short"),
			[32]byte{77, 249, 176, 89, 67, 8, 215, 248, 198, 94, 153, 202, 42, 202, 34, 10, 208, 251, 232, 58, 82, 34, 65, 47, 213, 83, 141, 76, 199, 18, 103, 133},
			nil,
		},
	}
	for _, c := range cases {
		ciphertextPtr, err := EncryptAES(&c.plaintext, &c.key, io.ReadFull)
		equal, m := errorsEqual(err, c.err)
		if !equal {
			t.Errorf("EncryptDecryptAES - encryptAES(%v, %v) - %s", c.plaintext, c.key, m)
		}
		plaintextPtr, err := DecryptAES(ciphertextPtr, &c.key)
		equal, m = errorsEqual(err, c.err)
		if !equal {
			t.Errorf("EncryptDecryptAES - decryptAES(%v, %v) - %s", *ciphertextPtr, c.key, m)
		}
		if !reflect.DeepEqual(*plaintextPtr, c.plaintext) {
			t.Errorf("EncryptDecryptAES - Plaintext '%v' is not expected plaintext '%v' (key '%v')", *plaintextPtr, c.plaintext, c.key)
			continue
		}
	}
}
