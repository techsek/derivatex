package internal

import (
	"golang.org/x/crypto/sha3"
)

func HashAndDestroy(data *[]byte) (digest *[32]byte) {
	digest = HashSHA3_256(data)
	ClearByteSlice(data)
	return digest
}

func HashSHA3_256(data *[]byte) (digest *[32]byte) {
	digest = new([32]byte)
	*digest = sha3.Sum256(*data)
	return digest
}
