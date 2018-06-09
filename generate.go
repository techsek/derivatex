package main

import (
	"io/ioutil"
)

// We just use sha3 as the input space is already 512 bits and is impossible to crack

func readMasterDigest() (masterDigest *[]byte, err error) {
	masterDigest = new([]byte)
	*masterDigest, err = ioutil.ReadFile("MasterPasswordDigest")
	if err != nil {
		clearByteSlice(masterDigest)
		return nil, err
	}
	err = dechecksumize(masterDigest)
	if err != nil {
		clearByteSlice(masterDigest)
		return nil, err
	}
	return masterDigest, nil
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

var asciiOrder map[int]asciiType = map[int]asciiType{
	0: asciiLowercase,
	1: asciiSymbol,
	2: asciiDigit,
	3: asciiUppercase,
}

func determineOffset(b byte, i int) (offset uint8) {
	offset = uint8(i)
	digest := hashSHA3_256(&[]byte{b})
	for _, b := range digest {
		offset += b
	}
	return offset
}

func determinePassword(masterDigest *[]byte, websiteName []byte, passwordLength int) string {
	// TODO passwordLength > 4

	// Determine initial password of length passwordLength
	input := new([]byte)
	*input = append(*masterDigest, websiteName...)
	digest := hashAndDestroy(input) // 32 ASCII characters
	password := (*digest)[:]

	// Extends the password with further hashing if the length is bigger than 32 characters
	for len(password) < passwordLength {
		deeperDigest := hashSHA3_256(&password)
		password = append(password, (*deeperDigest)[:]...)
	}
	password = password[:passwordLength]

	for i := range password {
		password[i] = determineOffset(password[i], i)
		if i < len(asciiOrder) { // ensure type of character for the first few characters
			for byteAsciiType(password[i]) != asciiOrder[i] {
				password[i] = (password[i] + 3) % 127 // 127 is the max of all possible ASCII characters of interest
			}
		} else {
			for byteAsciiType(password[i]) == asciiOther {
				password[i] = (password[i] + 3) % 127
			}
		}
	}
	return string(password)
}

// TODO generate RSA keys etc.
