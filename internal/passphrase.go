package internal

import (
	"github.com/castillobgr/sententia"
	"github.com/techsek/derivatex/constants"
	"golang.org/x/crypto/argon2"
)

// TODO implement our own passphrases with randsource and testable
func MakePassphrase() (passphrase string, err error) {
	passphrase, err = sententia.Make("{{ adjective }} {{ noun }}")
	if err != nil {
		return "", err
	}
	return passphrase, nil
}

func MakeKey(passphrase *[]byte) (key *[32]byte) {
	key = new([32]byte)
	keySlice := argon2.IDKey(*passphrase, []byte{}, constants.PassphraseArgonTimeCost, constants.PassphraseArgonMemoryMB*1024, constants.PassphraseArgonParallelism, 32)
	copy((*key)[:], keySlice)
	ClearByteSlice(&keySlice)
	return key
}
