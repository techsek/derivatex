package main

import (
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
			asciiOther,
		},
		{
			byte(150),
			asciiOther,
		},
	}
	for _, c := range cases {
		out := byteAsciiType(c.b)
		if out != c.t {
			t.Errorf("byteAsciiType(%v) == %v want %v", c.b, out, c.t)
		}
	}
}

func Test_determinePassword(t *testing.T) {
	cases := []struct {
		masterDigest   []byte
		websiteName    []byte
		passwordLength int
		password       string
	}{
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			0,
			``,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			2,
			`t9`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			4,
			`t9&1`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			10,
			`t9&1J&/Ky>`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("facebook"),
			10,
			`C?z41&r(k-`,
		},
		{
			[]byte{17, 5, 2, 85, 178, 255, 0, 29},
			[]byte("google"),
			50,
			`t9&1J&/Ky>16U-u7spOrT/6.MDF"Yt1TRO*@UzizwZ4'66Gvh:`,
		},
	}
	for _, c := range cases {
		out := determinePassword(&c.masterDigest, c.websiteName, c.passwordLength)
		if out != c.password {
			t.Errorf("byteAsciiType(%v, %s, %d) == %s want %s", c.masterDigest, string(c.websiteName), c.passwordLength, out, c.password)
		}
	}
}
