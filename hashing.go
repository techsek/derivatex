package main

import (
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

func getArgonTime() int64 {
	start := time.Now()
	argon2.IDKey([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}, 10, argonMemoryMB*1024, argonParallelism, argonDigestSize)
	elapsed := time.Since(start)
	return elapsed.Nanoseconds() / 12
}

func hashAndDestroy(data *[]byte) (digest *[32]byte) {
	digest = hashSHA3_256(data)
	clearByteSlice(data)
	return digest
}

func hashSHA3_256(data *[]byte) (digest *[32]byte) {
	digest = new([32]byte)
	*digest = sha3.Sum256(*data)
	return digest
}
