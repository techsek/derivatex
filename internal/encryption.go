package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type ioReadFullFunc func(r io.Reader, buf []byte) (n int, err error)

func EncryptAES(plaintext *[]byte, key *[32]byte, ioReadFull ioReadFullFunc) (ciphertext *[]byte, err error) {
	block, err := aes.NewCipher((*key)[:])
	if err != nil {
		return nil, err
	}
	ciphertext = new([]byte)
	*ciphertext = make([]byte, aes.BlockSize+len(*plaintext))
	iv := (*ciphertext)[:aes.BlockSize]
	_, err = ioReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream((*ciphertext)[aes.BlockSize:], *plaintext)
	return ciphertext, nil
}

func DecryptAES(ciphertext *[]byte, key *[32]byte) (plaintext *[]byte, err error) {
	block, err := aes.NewCipher((*key)[:])
	if err != nil {
		return nil, err
	}
	if len(*ciphertext) < aes.BlockSize {
		return nil, errors.New("Invalid cipher size which should be bigger than block size")
	}
	plaintext = new([]byte)
	*plaintext = make([]byte, len(*ciphertext)-aes.BlockSize)
	copy(*plaintext, (*ciphertext)[aes.BlockSize:])
	iv := make([]byte, aes.BlockSize)
	copy(iv, (*ciphertext)[:aes.BlockSize])
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(*plaintext, *plaintext)
	return plaintext, nil
}
