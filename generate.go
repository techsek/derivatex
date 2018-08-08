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
	"strings"
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
	asciiLowercase asciiType = 0
	asciiUppercase asciiType = 1
	asciiDigit     asciiType = 2
	asciiSymbol    asciiType = 3
	asciiOther     asciiType = 4
)

type byteBounds struct {
	lower  uint8
	higher uint8
}

var (
	asciiDigitBounds     = []byteBounds{byteBounds{48, 57}}                                                               // 9
	asciiUppercaseBounds = []byteBounds{byteBounds{65, 90}}                                                               // 25
	asciiLowercaseBounds = []byteBounds{byteBounds{97, 122}}                                                              // 25
	asciiSymbolBounds    = []byteBounds{byteBounds{33, 47}, byteBounds{58, 64}, byteBounds{91, 96}, byteBounds{123, 126}} // 28
) // total of 87 characters

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

func determinePassword(masterDigest *[]byte, websiteName []byte, user []byte, passwordLength uint8, round uint16, unallowedCharacters unallowedCharactersType) string {
	// Hashes masterDigest+websiteName to obtain an initial
	input := new([]byte)
	*input = append(*masterDigest, websiteName...)
	*input = append(*input, user...)
	digest := hashAndDestroy(input) // 32 ASCII characters
	// Rounds of password (to renew password, in example)
	var digestSlicePtr *[]byte = new([]byte)
	var k uint16
	for k = 1; k < round; k++ {
		*digestSlicePtr = (*digest)[:]
		digest = hashSHA3_256(digestSlicePtr) // additional SHA3 for more rounds
	}
	var password []byte = (*digest)[:]

	// Pseudo Random generator initialization
	randSource := rand.NewSource(int64(binary.BigEndian.Uint64(password)))

	// Extends the password using the pseudo random generator, if needed
	for uint8(len(password)) < passwordLength {
		password = append(password, byte(rand.Int()%256))
	}

	// Shortens the password from the digest, if needed
	password = password[:passwordLength]

	// Create and shuffle an initial order of Ascii character types
	var asciiOrder []asciiType
	lowercaseAllowed := len(unallowedCharacters[asciiLowercase]) < len(lowercases)
	uppercaseAllowed := len(unallowedCharacters[asciiUppercase]) < len(uppercases)
	digitAllowed := len(unallowedCharacters[asciiDigit]) < len(digits)
	symbolAllowed := len(unallowedCharacters[asciiSymbol]) < len(symbols)
	if lowercaseAllowed {
		asciiOrder = append(asciiOrder, asciiLowercase)
	}
	if uppercaseAllowed {
		asciiOrder = append(asciiOrder, asciiUppercase)
	}
	if digitAllowed {
		asciiOrder = append(asciiOrder, asciiDigit)
	}
	if symbolAllowed {
		asciiOrder = append(asciiOrder, asciiSymbol)
	}
	if len(asciiOrder) == 0 { // all characters are unallowed
		return ""
	}
	for len(asciiOrder) < int(passwordLength) {
		asciiOrder = append(asciiOrder, asciiOrder...)
	}
	asciiOrder = asciiOrder[:passwordLength]
	shuffleAsciiOrder(&asciiOrder, randSource)
	if len(asciiOrder) > 1 {
		// Shuffle more to get a lowercase or uppercase as the first character (if possible with flags)
		if lowercaseAllowed && uppercaseAllowed {
			for asciiOrder[0] != asciiLowercase && asciiOrder[0] != asciiUppercase {
				shuffleAsciiOrder(&asciiOrder, randSource)
			}
		} else if lowercaseAllowed {
			for asciiOrder[0] != asciiLowercase {
				shuffleAsciiOrder(&asciiOrder, randSource)
			}
		} else if uppercaseAllowed {
			for asciiOrder[0] != asciiUppercase {
				shuffleAsciiOrder(&asciiOrder, randSource)
			}
		}
	}
	for i := range password {
		for byteAsciiType(password[i]) != asciiOrder[i] || strings.Contains(unallowedCharacters[byteAsciiType(password[i])], string(password[i])) {
			password[i] = (password[i] + byte(randSource.Int63())) % 127 // 127 is the max of all possible ASCII characters of interest
		}
	}
	return string(password)
}

func shuffleAsciiOrder(asciiOrder *[]asciiType, randSource rand.Source) {
	var i, j int
	for i = len(*asciiOrder) - 1; i > 0; i-- {
		j = int(randSource.Int63()) % (i + 1)
		(*asciiOrder)[i], (*asciiOrder)[j] = (*asciiOrder)[j], (*asciiOrder)[i]
	}
}

type unallowedCharactersType map[asciiType]string

func (unallowedCharacters *unallowedCharactersType) serialize() (s string) {
	for k := range *unallowedCharacters {
		s += (*unallowedCharacters)[k]
	}
	return s
}

func (unallowedCharacters *unallowedCharactersType) isAnythingAllowed() bool {
	if len((*unallowedCharacters)[asciiDigit]) < len(digits) {
		return true
	}
	if len((*unallowedCharacters)[asciiSymbol]) < len(symbols) {
		return true
	}
	if len((*unallowedCharacters)[asciiLowercase]) < len(lowercases) {
		return true
	}
	if len((*unallowedCharacters)[asciiUppercase]) < len(uppercases) {
		return true
	}
	return false
}

func buildUnallowedCharacters(noSymbol, noDigit, noUppercase, noLowercase bool, excludeCharacters string) (unallowedCharacters unallowedCharactersType) {
	unallowedCharacters = make(unallowedCharactersType)
	unallowedCharacters[asciiSymbol] = ""
	unallowedCharacters[asciiDigit] = ""
	unallowedCharacters[asciiUppercase] = ""
	unallowedCharacters[asciiLowercase] = ""
	if noSymbol {
		unallowedCharacters[asciiSymbol] += symbols
	}
	if noDigit {
		unallowedCharacters[asciiDigit] += digits
	}
	if noUppercase {
		unallowedCharacters[asciiUppercase] += uppercases
	}
	if noLowercase {
		unallowedCharacters[asciiLowercase] += lowercases
	}
	for i := range excludeCharacters {
		t := byteAsciiType(excludeCharacters[i])
		if !strings.Contains(unallowedCharacters[t], string(excludeCharacters[i])) {
			unallowedCharacters[t] += string(excludeCharacters[i])
		}
	}
	return unallowedCharacters
}
