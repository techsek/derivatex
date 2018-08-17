package internal

import (
	"github.com/techsek/derivatex/constants"
	"golang.org/x/crypto/argon2"
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

func HashArgon2ID_256(source *[32]byte, salt *[32]byte) (digest *[]byte) {
	digest = new([]byte)
	*digest = argon2.IDKey((*source)[:], (*salt)[:], constants.PassphraseArgonTimeCost, constants.PassphraseArgonMemoryMB*1024, constants.PassphraseArgonParallelism, constants.PassphraseArgonDigestSize)
	return digest
}
