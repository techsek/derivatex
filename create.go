package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/argon2"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func createMasterDigest(masterPasswordSHA3 *[32]byte, birthdateSHA3 *[32]byte, timeCost uint32) (masterDigest *[]byte) {
	masterDigest = new([]byte)
	*masterDigest = argon2.IDKey((*masterPasswordSHA3)[:], (*birthdateSHA3)[:], timeCost, argonMemoryMB*1024, argonParallelism, argonDigestSize)
	return masterDigest
}

func writeMasterDigest(masterDigest *[]byte) error {
	checksumize(masterDigest)
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dir+"/MasterPasswordDigest", *masterDigest, 0644)
}

func showHashProgress(timeCost uint32) {
	bar := pb.StartNew(int(timeCost))
	bar.SetRefreshRate(time.Millisecond * 50)
	bar.ShowCounters = false
	for i := 0; i < int(timeCost); i++ {
		bar.Increment()
		time.Sleep(time.Nanosecond * time.Duration(argonTimeNs))
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
