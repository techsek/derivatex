package internal

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/techsek/derivatex/constants"
	"golang.org/x/crypto/argon2"
)

func GetArgonTimePerRound() int64 {
	start := time.Now()
	argon2.IDKey([]byte{}, []byte{}, constants.ArgonTestRounds, constants.ArgonMemoryMB*1024, constants.ArgonParallelism, constants.ArgonDigestSize)
	elapsed := time.Since(start)
	return int64(elapsed.Nanoseconds()/int64(constants.ArgonTestRounds)) / 1000000
}

func CreateSeed(masterPasswordSHA3 *[32]byte, birthdateSHA3 *[32]byte) (seed *[]byte) {
	seed = new([]byte)
	*seed = argon2.IDKey((*masterPasswordSHA3)[:], (*birthdateSHA3)[:], constants.ArgonTimeCost, constants.ArgonMemoryMB*1024, constants.ArgonParallelism, constants.ArgonDigestSize)
	return seed
}

func WriteSeed(defaultUser string, protection string, seed *[]byte) error {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	var content = new([]byte)
	*content = append(*content, []byte("Default user: "+defaultUser+"\n")...)
	*content = append(*content, []byte("Protection: "+protection+"\n")...)
	*content = append(*content, []byte("Secret Seed: ")...)
	*content = append(*content, []byte(base64.StdEncoding.EncodeToString(*seed))...)
	err = ioutil.WriteFile(dir+"/"+constants.SeedFilename, *content, 0644)
	ClearByteSlice(content)
	return err
}
