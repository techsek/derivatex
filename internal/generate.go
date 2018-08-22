package internal

import (
	"encoding/binary"
	"log"
	"math/rand"
	"strings"

	"github.com/techsek/derivatex/constants"
)

func MakePasswordDigest(clientSeed *[]byte, website, user string, passwordDerivationVersion uint16) (passwordDigest *[32]byte) {
	input := new([]byte)
	*input = append(*clientSeed, []byte(website)...)
	if passwordDerivationVersion > 1 {
		*input = append(*input, []byte(user)...)
	}
	passwordDigest = HashAndDestroy(input) // TODO homomorphic sha3 256 on server with serverSeed+clientSeed
	return passwordDigest
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

type unallowedCharactersType map[asciiType]string

func SatisfyPassword(passwordDigest *[32]byte, passwordLength uint8, round uint16, unallowedCharacters unallowedCharactersType, passwordDerivationVersion uint16) string {
	// Rounds of password (to renew password, in example)
	var digestSlicePtr = new([]byte)
	var k uint16
	for k = 1; k < round; k++ {
		*digestSlicePtr = (*passwordDigest)[:]
		passwordDigest = HashSHA3_256(digestSlicePtr) // additional SHA3 for more rounds
	}
	var password = (*passwordDigest)[:]

	// Pseudo Random generator initialization
	var randInt func() int64
	if passwordDerivationVersion < 3 {
		source := rand.NewSource(int64(binary.BigEndian.Uint64(password)))
		randInt = source.Int63
	} else {
		source := newSource(binary.BigEndian.Uint64(password))
		randInt = source.randInt64
	}

	// Extends the password using the pseudo random generator, if needed
	for uint8(len(password)) < passwordLength {
		password = append(password, byte(randInt()%256))
	}

	// Shortens the password from the digest, if needed
	password = password[:passwordLength]

	// Create and shuffle an initial order of Ascii character types
	var asciiOrder []asciiType
	lowercaseAllowed := len(unallowedCharacters[asciiLowercase]) < len(constants.Lowercases)
	uppercaseAllowed := len(unallowedCharacters[asciiUppercase]) < len(constants.Uppercases)
	digitAllowed := len(unallowedCharacters[asciiDigit]) < len(constants.Digits)
	symbolAllowed := len(unallowedCharacters[asciiSymbol]) < len(constants.Symbols)
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
	shuffleASCIIOrder(&asciiOrder, randInt)
	if len(asciiOrder) > 1 {
		// Shuffle more to get a lowercase or uppercase as the first character (if possible with flags)
		if lowercaseAllowed && uppercaseAllowed {
			for asciiOrder[0] != asciiLowercase && asciiOrder[0] != asciiUppercase {
				shuffleASCIIOrder(&asciiOrder, randInt)
			}
		} else if lowercaseAllowed {
			for asciiOrder[0] != asciiLowercase {
				shuffleASCIIOrder(&asciiOrder, randInt)
			}
		} else if uppercaseAllowed {
			for asciiOrder[0] != asciiUppercase {
				shuffleASCIIOrder(&asciiOrder, randInt)
			}
		}
	}
	for i := range password {
		for byteASCIIType(password[i]) != asciiOrder[i] || strings.Contains(unallowedCharacters[byteASCIIType(password[i])], string(password[i])) {
			password[i] = (password[i] + byte(randInt())) % 127 // 127 is the max of all possible ASCII characters of interest
		}
	}
	return string(password)
}

func BuildUnallowedCharacters(noSymbol, noDigit, noUppercase, noLowercase bool, excludeCharacters string) (unallowedCharacters unallowedCharactersType) {
	unallowedCharacters = make(unallowedCharactersType)
	unallowedCharacters[asciiSymbol] = ""
	unallowedCharacters[asciiDigit] = ""
	unallowedCharacters[asciiUppercase] = ""
	unallowedCharacters[asciiLowercase] = ""
	if noSymbol {
		unallowedCharacters[asciiSymbol] += constants.Symbols
	}
	if noDigit {
		unallowedCharacters[asciiDigit] += constants.Digits
	}
	if noUppercase {
		unallowedCharacters[asciiUppercase] += constants.Uppercases
	}
	if noLowercase {
		unallowedCharacters[asciiLowercase] += constants.Lowercases
	}
	for i := range excludeCharacters {
		t := byteASCIIType(excludeCharacters[i])
		if !strings.Contains(unallowedCharacters[t], string(excludeCharacters[i])) {
			unallowedCharacters[t] += string(excludeCharacters[i])
		}
	}
	return unallowedCharacters
}

func (unallowedCharacters *unallowedCharactersType) IsAnythingAllowed() bool {
	if len((*unallowedCharacters)[asciiDigit]) < len(constants.Digits) {
		return true
	}
	if len((*unallowedCharacters)[asciiSymbol]) < len(constants.Symbols) {
		return true
	}
	if len((*unallowedCharacters)[asciiLowercase]) < len(constants.Lowercases) {
		return true
	}
	if len((*unallowedCharacters)[asciiUppercase]) < len(constants.Uppercases) {
		return true
	}
	return false
}

func (unallowedCharacters *unallowedCharactersType) Serialize() (s string) {
	for k := range *unallowedCharacters {
		s += (*unallowedCharacters)[k]
	}
	return s
}

func byteInBounds(b byte, bounds []byteBounds) bool {
	for _, bound := range bounds {
		if b >= bound.lower && b <= bound.higher {
			return true
		}
	}
	return false
}

func byteASCIIType(b byte) asciiType {
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

func shuffleASCIIOrder(asciiOrder *[]asciiType, randInt func() int64) {
	var i, j int
	for i = len(*asciiOrder) - 1; i > 0; i-- {
		j = int(randInt()) % (i + 1)
		if j < 0 || j > len(*asciiOrder) {
			log.Println(j)
		}
		(*asciiOrder)[i], (*asciiOrder)[j] = (*asciiOrder)[j], (*asciiOrder)[i]
	}
}
