package internal

import (
	"errors"
	"reflect"

	"golang.org/x/crypto/sha3"
)

func Checksumize(data *[]byte) {
	digest := sha3.Sum256(*data)
	checksum := digest[0:4]
	*data = append(*data, checksum...)
}

func Dechecksumize(data *[]byte) error {
	if data == nil {
		return errors.New("No data to verify checksum")
	}
	L := len(*data)
	if L < 4 {
		return errors.New("Checksumed data is not long enough to contain the checksum")
	}
	checksum := (*data)[L-4:]
	*data = (*data)[:L-4]
	digest := sha3.Sum256(*data)
	checksum2 := digest[:4]
	if !reflect.DeepEqual(checksum, checksum2) {
		return errors.New("Checksum verification failed")
	}
	return nil
}
