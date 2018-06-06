package main

import (
	"log"
	"strconv"
	"time"

	"golang.org/x/crypto/sha3"

	ps "github.com/nbutton23/zxcvbn-go"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func evaluatePassword(masterPassword *[]byte) (safety uint8, message string) {
	analysis := ps.PasswordStrength(string(*masterPassword), []string{})
	message = "Your password has a security of " + strconv.FormatFloat(analysis.Entropy, 'f', 2, 64) + " bits, equivalent to a suitcase lock of " + strconv.FormatFloat(analysis.Entropy*0.30103, 'f', 0, 64) + " digits. It would take " + analysis.CrackTimeDisplay + " to crack it. "
	if analysis.Entropy > 30 {
		safety = 1
	}
	if analysis.Entropy > 50 {
		safety = 2
	}
	return safety, message
}

func determineArgonTimeCost(b []byte) (timeCost uint32) {
	digest := sha3.Sum256(b)
	offset := uint32(bytesToUint64(digest[:]))
	for timeCost < 100 || timeCost > 200 {
		timeCost = (timeCost + offset) % 201
	}
	log.Println(timeCost)
	return timeCost
}

func createMasterDigest(masterPassword *[]byte, birthdate *[]byte, timeCost uint32) (masterDigest []byte) {
	passwordDigest := hashAndDestroy(masterPassword)
	birthdateDigest := hashAndDestroy(birthdate)
	masterDigest = masterHash(passwordDigest, birthdateDigest, timeCost)
	return masterDigest
}

func showHashProgress(timeCost int) {
	bar := pb.StartNew(timeCost)
	bar.SetRefreshRate(time.Millisecond * 50)
	bar.ShowCounters = false
	for i := 0; i < timeCost; i++ {
		bar.Increment()
		time.Sleep(time.Nanosecond * time.Duration(argonTimeNs))
	}
	bar.FinishPrint("About to finish...")
}

func dateIsValid(date string) bool {
	_, err := time.Parse("02/01/2006", date)
	if err != nil {
		return false
	}
	return true
}
