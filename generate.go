package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
)

// We just use sha3 as the input space is already 512 bits and is impossible to crack

func readMasterDigest() (defaultUser string, protection string, masterDigest *[]byte, err error) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return "", "", nil, err
	}
	var content *[]byte = new([]byte)
	defer clearByteSlice(content)
	*content, err = ioutil.ReadFile(dir + "/" + masterDigestFilename)
	if err != nil {
		return "", "", nil, err
	}

	// Reading the file step by step instead of with bytes.Split() to avoid using more memory than necessary for security purposes
	var i int
	i = bytes.Index(*content, []byte("Default user: "))
	if i < 0 {
		return "", "", nil, errors.New("'Default user: ' not found in secret digest file")
	}
	if i > 0 {
		return "", "", nil, errors.New("'Default user: ' must be the start of the secret digest file")
	}
	clearAndTrim(content, i+len([]byte("Default user: ")))
	i = bytes.Index(*content, []byte("\n"))
	if i < 0 {
		return "", "", nil, errors.New("New line not found after 'Default user: ' in secret digest file")
	}
	defaultUser = string((*content)[:i])
	clearAndTrim(content, i+len([]byte("\n")))
	i = bytes.Index(*content, []byte("Protection: "))
	if i < 0 {
		return "", "", nil, errors.New("'Protection: ' not found in secret digest file")
	}
	clearAndTrim(content, i+len([]byte("Protection: ")))
	i = bytes.Index(*content, []byte("\n"))
	if i < 0 {
		return "", "", nil, errors.New("New line not found after 'Protection: ' in secret digest file")
	}
	protection = string((*content)[:i])
	clearAndTrim(content, i+len([]byte("\n")))
	i = bytes.Index(*content, []byte("Secret Digest: "))
	if i < 0 {
		return "", "", nil, errors.New("'Secret Digest: ' not found in secret digest file")
	}
	clearAndTrim(content, i+len([]byte("Secret Digest: ")))
	masterDigest = new([]byte)
	*masterDigest, err = base64.StdEncoding.DecodeString(string(*content))
	clearByteSlice(content)
	if err != nil {
		return "", "", nil, err
	}
	return defaultUser, protection, masterDigest, nil
}

type asciiType uint8

const (
	asciiDigit     asciiType = 0
	asciiLowercase asciiType = 1
	asciiUppercase asciiType = 2
	asciiSymbol    asciiType = 3
	asciiOther     asciiType = 4
)

type byteBounds struct {
	lower  uint8
	higher uint8
}

var (
	asciiDigitBounds     = []byteBounds{byteBounds{48, 57}}
	asciiUppercaseBounds = []byteBounds{byteBounds{65, 90}}
	asciiLowercaseBounds = []byteBounds{byteBounds{97, 122}}
	asciiSymbolBounds    = []byteBounds{byteBounds{33, 47}, byteBounds{58, 64}, byteBounds{94, 95}}
)

func byteInBounds(b byte, bounds []byteBounds) bool {
	for _, bound := range bounds {
		if b >= bound.lower && b <= bound.higher {
			return true
		}
	}
	return false
}

func byteAsciiType(b byte) asciiType {
	if byteInBounds(b, asciiSymbolBounds) {
		return asciiSymbol
	}
	if byteInBounds(b, asciiLowercaseBounds) {
		return asciiLowercase
	}
	if byteInBounds(b, asciiUppercaseBounds) {
		return asciiUppercase
	}
	if byteInBounds(b, asciiDigitBounds) {
		return asciiDigit
	}
	return asciiOther
}

func determinePassword(masterDigest *[]byte, websiteName []byte, passwordLength int, round int) string {
	// TODO passwordLength < 4 give warning

	// Hashes masterDigest+websiteName to obtain an initial
	input := new([]byte)
	*input = append(*masterDigest, websiteName...)
	digest := hashAndDestroy(input) // 32 ASCII characters
	// Rounds of password (to renew password, in example)
	var digestSlicePtr *[]byte = new([]byte)
	for i := 1; i < round; i++ {
		*digestSlicePtr = (*digest)[:]
		digest = hashSHA3_256(digestSlicePtr) // additional SHA3 for more rounds
	}
	var password []byte = (*digest)[:]

	// Pseudo Random generator initialization
	randSource := rand.NewSource(int64(binary.BigEndian.Uint64(password)))

	// Extends the password using the pseudo random generator, if needed
	for len(password) < passwordLength {
		password = append(password, byte(rand.Int()%256))
	}

	// Shortens the password from the digest, if needed
	password = password[:passwordLength]

	var asciiOrder map[int]asciiType = map[int]asciiType{
		0: asciiDigit,
		1: asciiSymbol,
		3: asciiLowercase,
		4: asciiUppercase,
	}
	var i, j int
	for asciiOrder[0] != asciiLowercase && asciiOrder[0] != asciiUppercase {
		i = int(randSource.Int63()) % len(asciiOrder)
		j = int(randSource.Int63()) % len(asciiOrder)
		for j == i {
			j = int(randSource.Int63()) % len(asciiOrder)
		}
		asciiOrder[i], asciiOrder[j] = asciiOrder[j], asciiOrder[i]
	}

	for i := range password {
		if i == 0 {

		}
		if i < len(asciiOrder) { // ensure type of character for the first few characters
			for byteAsciiType(password[i]) != asciiOrder[i] {
				password[i] = (password[i] + byte(randSource.Int63())) % 127 // 127 is the max of all possible ASCII characters of interest
			}
		} else {
			for byteAsciiType(password[i]) == asciiOther {
				password[i] = (password[i] + byte(randSource.Int63())) % 127
			}
		}
	}
	return string(password)
}

// TODO generate RSA keys etc.
