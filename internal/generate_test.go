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

func Test_DeterminePassword(t *testing.T) {
	cases := []struct {
		seed                []byte
		websiteName         []byte
		user                []byte
		passwordLength      uint8
		round               uint16
		unallowedCharacters unallowedCharactersType
		password            string
	}{
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			0,
			1,
			unallowedCharactersType{},
			``,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			2,
			1,
			unallowedCharactersType{},
			`Fq`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			4,
			1,
			unallowedCharactersType{},
			`jA9;`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			10,
			1,
			unallowedCharactersType{},
			`U1b5&O/Zyu`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("facebook"),
			[]byte(""),
			10,
			1,
			unallowedCharactersType{},
			`Otf}Aw82T*`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			50,
			1,
			unallowedCharactersType{},
			`zX'l+6WYyx.e&8G8>647sKmn93AV^Jb]d_1Zz3K.-y7Z*j4Z,H`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			10,
			1,
			BuildUnallowedCharacters(false, false, true, true, ""),
			`<636/\/)38`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte(""),
			10,
			1,
			BuildUnallowedCharacters(true, false, false, false, ""),
			`j3nlfCL08L`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte("a@b.com"),
			50,
			1,
			unallowedCharactersType{},
			`oqYKMuD6~525H/X"8Y5qf@~irQDn,y#{7Zea*54s+M85Hg^7'B`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			[]byte("b@a.com"),
			50,
			1,
			unallowedCharactersType{},
			`JW7Q5#,r9$@^s778oxHI29k78dKsix"/!h;wI}:90KsVRZdO|H`,
		},
	}
	for _, c := range cases {
		out := DeterminePassword(&c.seed, c.websiteName, c.user, c.passwordLength, c.round, c.unallowedCharacters)
		if out != c.password {
			t.Errorf("DeterminePassword(%v, %s, %s, %d) == %s want %s", c.seed, string(c.websiteName), string(c.user), c.passwordLength, out, c.password)
		}
	}
}
