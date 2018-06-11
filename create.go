package main

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func createMasterDigest(masterPasswordSHA3 *[32]byte, birthdateSHA3 *[32]byte) (masterDigest *[]byte) {
	masterDigest = new([]byte)
	*masterDigest = argon2.IDKey((*masterPasswordSHA3)[:], (*birthdateSHA3)[:], argonTimeCost, argonMemoryMB*1024, argonParallelism, argonDigestSize)
	return masterDigest
}

func getArgonTimePerRound() int64 {
	start := time.Now()
	argon2.IDKey([]byte{}, []byte{}, argonTestRounds, argonMemoryMB*1024, argonParallelism, argonDigestSize)
	elapsed := time.Since(start)
	return int64(elapsed.Nanoseconds()/int64(argonTestRounds)) / 1000000
}

func writeMasterDigest(identifiant string, protection string, masterDigest *[]byte) error {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	var content *[]byte = new([]byte)
	*content = append(*content, []byte("Identifiant: "+identifiant+"\n")...)
	*content = append(*content, []byte("Protection: "+protection+"\n")...)
	*content = append(*content, []byte("Secret Digest: ")...)
	*content = append(*content, []byte(base64.StdEncoding.EncodeToString(*masterDigest))...)
	err = ioutil.WriteFile(dir+"/"+masterDigestFilename, *content, 0644)
	clearByteSlice(content)
	return err
}

func showHashProgress(argonTimePerRound int64) {
	bar := pb.StartNew(int(argonTimeCost))
	bar.SetRefreshRate(time.Millisecond * 150)
	bar.ShowCounters = false
	for i := 0; i < int(argonTimeCost); i++ {
		bar.Increment()
		time.Sleep(time.Millisecond * time.Duration(argonTimePerRound))
	}
	bar.FinishPrint("About to finish...")
}

func dateIsValid(date *[]byte) bool {
	_, err := time.Parse("02/01/2006", string(*date))
	if err != nil {
		return false
	}
	return true
}

func byteSlicesEqual(b1 *[]byte, b2 *[]byte) bool {
	if len(*b1) != len(*b2) {
		return false
	}
	for i := range *b1 {
		if (*b1)[i] != (*b2)[i] {
			return false
		}
	}
	return true
}

func byteArrays32Equal(b1 *[32]byte, b2 *[32]byte) bool {
	for i := range *b1 {
		if (*b1)[i] != (*b2)[i] {
			return false
		}
	}
	return true
}
