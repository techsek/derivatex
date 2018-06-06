package main

import (
	"encoding/base64"
	"encoding/binary"
	"math"
)

func bytesToBase64(bytes []byte) (b64String string) {
	b64String = base64.StdEncoding.EncodeToString(bytes)
	return b64String
}

func base64ToBytes(b64String string) (bytes []byte) {
	bytes, err := base64.StdEncoding.DecodeString(b64String)
	if err != nil {
		panic(err) // TODO
	}
	return bytes
}

func stringToBytes(s string) []byte {
	return []byte(s)
}

func bytesToString(b []byte) string {
	return string(b)
}

func uint64ToBytes(i uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, i)
	return b
}

func bytesToUint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

func int64ToBytes(i int64) []byte {
	return uint64ToBytes(uint64(i))
}

func bytesToInt64(b []byte) int64 {
	return int64(bytesToUint64(b))
}

func uint8ToBytes(i uint8) []byte {
	return []byte{byte(i)}
}

func bytesToUint8(b []byte) uint8 {
	return uint8(b[0])
}

func float64ToBytes(f float64) []byte {
	b := make([]byte, 8)
	bits := math.Float64bits(f)
	binary.LittleEndian.PutUint64(b, bits)
	return b
}

func bytesToFloat64(b []byte) float64 {
	bits := binary.LittleEndian.Uint64(b)
	return math.Float64frombits(bits)
}
