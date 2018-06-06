package main

import (
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

func masterHash(passwordDigest []byte, birthdateDigest []byte, argonTimeCost uint32) (key []byte) {
	// birthdateDigest is used as the salt
	key = argon2.IDKey(passwordDigest, birthdateDigest, argonTimeCost, 64*1024, 4, 64)
	checksumize(&key)
	return key
}

func getArgonTime() int64 {
	start := time.Now()
	argon2.IDKey([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}, 20, 64*1024, 4, 64)
	elapsed := time.Since(start)
	return elapsed.Nanoseconds() / 32
}

func hashAndDestroy(data *[]byte) (digest []byte) {
	digest64 := sha3.Sum512(*data)
	digest = digest64[:]
	for i := range digest64 {
		digest64[i] = byte(0)
	}
	*data = nil // TODO set all bytes to zeros
	data = nil
	return digest
}
