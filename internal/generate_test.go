package internal

import (
	"math/rand"
	"reflect"
	"testing"
)

func Test_byteInBounds(t *testing.T) {
	cases := []struct {
		b      byte
		bounds []byteBounds
		in     bool
	}{
		{
			byte(33),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			true,
		},
		{
			byte(40),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			true,
		},
		{
			byte(47),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			true,
		},
		{
			byte(58),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			true,
		},
		{
			byte(64),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			true,
		},
		{
			byte(52),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			false,
		},
		{
			byte(120),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			false,
		},
		{
			byte(0),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			false,
		},
		{
			byte(255),
			[]byteBounds{byteBounds{33, 47}, byteBounds{58, 64}},
			false,
		},
	}
	for _, c := range cases {
		out := byteInBounds(c.b, c.bounds)
		if out != c.in {
			t.Errorf("byteInBounds(%v, %v) == %v want %v", c.b, c.bounds, out, c.in)
		}
	}
}

func Test_byteAsciiType(t *testing.T) {
	cases := []struct {
		b byte
		t asciiType
	}{
		{
			byte(0),
			asciiOther,
		},
		{
			byte(33),
			asciiSymbol,
		},
		{
			byte(50),
			asciiDigit,
		},
		{
			byte(62),
			asciiSymbol,
		},
		{
			byte(68),
			asciiUppercase,
		},
		{
			byte(100),
			asciiLowercase,
		},
		{
			byte(125),
			asciiSymbol,
		},
		{
			byte(150),
			asciiOther,
		},
	}
	for _, c := range cases {
		out := byteASCIIType(c.b)
		if out != c.t {
			t.Errorf("byteAsciiType(%v) == %v want %v", c.b, out, c.t)
		}
	}
}

func Test_shuffleAsciiOrder(t *testing.T) {
	cases := []struct {
		asciiOrder         []asciiType
		randSource         rand.Source
		shuffledASCIIOrder []asciiType
	}{
		{
			[]asciiType{asciiLowercase},
			rand.NewSource(1),
			[]asciiType{asciiLowercase},
		},
		{
			[]asciiType{asciiLowercase, asciiUppercase},
			rand.NewSource(0),
			[]asciiType{asciiLowercase, asciiUppercase},
		},
		{
			[]asciiType{asciiLowercase, asciiUppercase},
			rand.NewSource(1),
			[]asciiType{asciiUppercase, asciiLowercase},
		},
		{
			[]asciiType{asciiLowercase, asciiUppercase, asciiDigit},
			rand.NewSource(10),
			[]asciiType{asciiUppercase, asciiDigit, asciiLowercase},
		},
		{
			[]asciiType{asciiLowercase, asciiUppercase, asciiSymbol},
			rand.NewSource(2645),
			[]asciiType{asciiSymbol, asciiLowercase, asciiUppercase},
		},
		{
			[]asciiType{asciiLowercase, asciiUppercase, asciiDigit, asciiSymbol},
			rand.NewSource(0),
			[]asciiType{asciiDigit, asciiSymbol, asciiLowercase, asciiUppercase},
		},
		{
			[]asciiType{asciiLowercase, asciiUppercase, asciiDigit, asciiSymbol},
			rand.NewSource(1),
			[]asciiType{asciiLowercase, asciiSymbol, asciiUppercase, asciiDigit},
		},
	}
	for _, c := range cases {
		shuffleASCIIOrder(&c.asciiOrder, c.randSource)
		if !reflect.DeepEqual(c.asciiOrder, c.shuffledASCIIOrder) {
			t.Errorf("shuffleAsciiOrder(&c.asciiOrder, c.randSource) == %v want %v", c.asciiOrder, c.shuffledASCIIOrder)
		}
	}
}

func Test_SatisfyPassword(t *testing.T) {
	cases := []struct {
		passwordDigest      [32]byte
		passwordLength      uint8
		round               uint16
		unallowedCharacters unallowedCharactersType
		password            string
	}{
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			0,
			1,
			unallowedCharactersType{},
			``,
		},
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			2,
			1,
			unallowedCharactersType{},
			`Fq`,
		},
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			4,
			1,
			unallowedCharactersType{},
			`jA9;`,
		},
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			10,
			1,
			unallowedCharactersType{},
			`U1b5&O/Zyu`,
		},
		{
			[32]byte{47, 245, 150, 209, 165, 136, 114, 40, 237, 204, 217, 246, 1, 3, 162, 139, 129, 118, 158, 112, 235, 62, 56, 205, 248, 78, 172, 151, 94, 146, 57, 158},
			10,
			1,
			unallowedCharactersType{},
			`Otf}Aw82T*`,
		},
		{
			[32]byte{47, 245, 150, 209, 165, 136, 114, 40, 237, 204, 217, 246, 1, 3, 162, 139, 129, 118, 158, 112, 235, 62, 56, 205, 248, 78, 172, 151, 94, 146, 57, 158},
			10,
			2,
			unallowedCharactersType{},
			`L;ggD48X>t`,
		},
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			50,
			1,
			unallowedCharactersType{},
			`zX'l+6WYyx.e&8G8>647sKmn93AV^Jb]d_1Zz3K.-y7Z*j4Z,H`,
		},
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			10,
			1,
			BuildUnallowedCharacters(false, false, true, true, ""),
			`<636/\/)38`,
		},
		{
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
			10,
			1,
			BuildUnallowedCharacters(true, false, false, false, ""),
			`j3nlfCL08L`,
		},
		{
			[32]byte{156, 176, 130, 203, 252, 241, 158, 62, 20, 50, 82, 100, 43, 23, 148, 2, 180, 43, 42, 72, 204, 24, 21, 159, 110, 52, 244, 177, 101, 165, 79, 195},
			50,
			1,
			unallowedCharactersType{},
			`IF>t8UyMCSRU3Mt0\4*<l=sf5l8Le{n2{'85RO0Iij=$04{d&i`,
		},
	}
	for _, c := range cases {
		out := SatisfyPassword(&c.passwordDigest, c.passwordLength, c.round, c.unallowedCharacters)
		if out != c.password {
			t.Errorf("SatisfyPassword(%v, %d, %d, %v) == %s want %s", c.passwordDigest, c.passwordLength, c.round, c.unallowedCharacters, out, c.password)
		}
	}
}

func Test_MakePasswordDigest(t *testing.T) {
	cases := []struct {
		clientSeed                []byte
		website                   string
		user                      string
		passwordDerivationVersion uint16
		passwordDigest            [32]byte
	}{
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"google",
			"",
			1,
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"google",
			"a@a",
			1,
			[32]byte{173, 201, 139, 108, 102, 233, 47, 218, 121, 176, 142, 54, 143, 21, 28, 204, 115, 253, 79, 230, 151, 171, 237, 46, 77, 152, 189, 34, 89, 28, 149, 29},
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"google",
			"a@a",
			2,
			[32]byte{185, 242, 95, 80, 55, 165, 222, 43, 254, 100, 137, 204, 237, 145, 64, 91, 32, 95, 233, 127, 224, 227, 93, 181, 119, 207, 105, 188, 242, 37, 201, 176},
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"google",
			"a@b",
			2,
			[32]byte{200, 141, 104, 178, 93, 187, 175, 251, 199, 180, 11, 6, 238, 142, 52, 178, 253, 213, 245, 203, 2, 84, 55, 63, 47, 222, 235, 183, 91, 244, 110, 208},
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"google",
			"b@a",
			2,
			[32]byte{156, 176, 130, 203, 252, 241, 158, 62, 20, 50, 82, 100, 43, 23, 148, 2, 180, 43, 42, 72, 204, 24, 21, 159, 110, 52, 244, 177, 101, 165, 79, 195},
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"facebook",
			"",
			2,
			[32]byte{47, 245, 150, 209, 165, 136, 114, 40, 237, 204, 217, 246, 1, 3, 162, 139, 129, 118, 158, 112, 235, 62, 56, 205, 248, 78, 172, 151, 94, 146, 57, 158},
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			"facebook",
			"b@a",
			2,
			[32]byte{19, 141, 208, 165, 180, 187, 96, 201, 120, 246, 142, 94, 119, 37, 29, 252, 248, 226, 67, 158, 124, 58, 207, 193, 207, 225, 155, 97, 39, 104, 20, 182},
		},
	}
	for _, c := range cases {
		out := MakePasswordDigest(&c.clientSeed, c.website, c.user, c.passwordDerivationVersion)
		if !reflect.DeepEqual(*out, c.passwordDigest) {
			t.Errorf("MakePasswordDigest(%v, %s, %s, %d) == %v want %v", c.clientSeed, c.website, c.user, c.passwordDerivationVersion, *out, c.passwordDigest)
		}
	}
}
