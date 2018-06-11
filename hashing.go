package main

import (
	"golang.org/x/crypto/sha3"
)

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
