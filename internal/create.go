package internal

import (
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"time"

	ps "github.com/nbutton23/zxcvbn-go"
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

func EncryptSeed(seed *[]byte, passphrase *[]byte) (encryptedSeed *[]byte, err error) {
	key := MakeKey(passphrase) // Argon2ID
	ClearByteSlice(passphrase)
	Checksumize(seed)
	encryptedSeed, err = EncryptAES(seed, key, io.ReadFull)
	ClearByteSlice(seed)
	ClearByteArray32(key)
	if err != nil {
		ClearByteSlice(encryptedSeed)
		return nil, err
	}
	return encryptedSeed, nil
}

func DecryptSeed(encryptedSeed *[]byte, passphrase *[]byte) (seed *[]byte, err error) {
	key := MakeKey(passphrase) // Argon2ID
	ClearByteSlice(passphrase)
	seed, err = DecryptAES(encryptedSeed, key)
	ClearByteArray32(key)
	if err != nil {
		ClearByteSlice(seed)
		return nil, err
	}
	err = Dechecksumize(seed)
	if err != nil {
		ClearByteSlice(seed)
		return nil, err
	}
	return seed, nil
}

func CreateNonInteractive(masterPassword string, birthdate string, user string, passphrase string) (err error) {
	// TODO mutable strings to clear them all
	masterPasswordBytes := []byte(masterPassword)
	safety, _ := EvaluatePassword(&masterPasswordBytes)
	masterPasswordSHA3 := HashAndDestroy(&masterPasswordBytes)
	if safety == 0 {
		ClearByteArray32(masterPasswordSHA3)
		return errors.New("Your password is not safe, please enter a more complicated password.")
	}
	// TODO: what to do for safety == 1 ?
	birthdateBytes := []byte(birthdate)
	if !DateIsValid(&birthdateBytes) {
		ClearByteSlice(&birthdateBytes)
		return errors.New("The birthdate you entered is not valid.")
	}
	birthdateSHA3 := HashAndDestroy(&birthdateBytes)
	seed := CreateSeed(masterPasswordSHA3, birthdateSHA3)
	ClearByteArray32(masterPasswordSHA3)
	ClearByteArray32(birthdateSHA3)
	protection := "none"
	if passphrase != "" {
		protection = "passphrase"
		passphraseBytes := []byte(passphrase)
		encryptedSeed, err := EncryptSeed(seed, &passphraseBytes)
		if err != nil {
			return errors.New("The following error occurred when encrypting the seed: " + err.Error())
		}
		seed = encryptedSeed
	}
	err = WriteSeed(user, protection, seed)
	ClearByteSlice(seed)
	if err != nil {
		return errors.New("Error writing seed to file: " + err.Error())
	}
	return nil
}

func DateIsValid(date *[]byte) bool {
	_, err := time.Parse("02/01/2006", string(*date))
	if err != nil {
		return false
	}
	return true
}

func EvaluatePassword(masterPassword *[]byte) (safety uint8, message string) {
	analysis := ps.PasswordStrength(string(*masterPassword), []string{})
	// TODO find cracktime
	message = "Your password has an entropy of " + strconv.FormatFloat(analysis.Entropy, 'f', 2, 64) + " bits, equivalent to a suitcase lock of " + strconv.FormatFloat(analysis.Entropy*0.30103, 'f', 0, 64) + " digits."
	if analysis.Entropy > constants.MasterPasswordBitsSafe {
		safety = 1
	}
	if analysis.Entropy > constants.MasterPasswordBitsSafer {
		safety = 2
	}
	return safety, message
}
