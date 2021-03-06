package internal

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/fatih/color"
	"github.com/techsek/derivatex/constants"
	"golang.org/x/crypto/ssh/terminal"
)

func ReadInput(prompt string) (input string) {
	fmt.Print(color.HiMagentaString(prompt))
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		input = scanner.Text()
	}
	return input
}

func ReadSecret(prompt string) (secretPtr *[]byte, err error) {
	fmt.Print(color.HiMagentaString(prompt))
	secretPtr = new([]byte)
	*secretPtr, err = terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return nil, err
	}
	return secretPtr, nil
}

// We just use sha3 as the input space is already 512 bits and is impossible to crack
func ReadSeed() (defaultUser string, protection string, seed *[]byte, err error) {
	ex, err := os.Executable()
	if err != nil {
		return "", "", nil, err
	}
	dir := filepath.Dir(ex)
	var content = new([]byte)
	defer ClearByteSlice(content)
	*content, err = ioutil.ReadFile(dir + "/" + constants.SeedFilename)
	if err != nil {
		return "", "", nil, err
	}

	// Reading the file step by step instead of with bytes.Split() to avoid using more memory than necessary for security purposes
	var i int
	i = bytes.Index(*content, []byte("Default user: "))
	if i < 0 {
		return "", "", nil, errors.New("'Default user: ' not found in " + constants.SeedFilename)
	}
	if i > 0 {
		return "", "", nil, errors.New("'Default user: ' must be the start of " + constants.SeedFilename)
	}
	clearAndTrim(content, i+len([]byte("Default user: ")))
	i = bytes.Index(*content, []byte("\n"))
	if i < 0 {
		return "", "", nil, errors.New("New line not found after 'Default user: ' in " + constants.SeedFilename)
	}
	defaultUser = string((*content)[:i])
	clearAndTrim(content, i+len([]byte("\n")))
	i = bytes.Index(*content, []byte("Protection: "))
	if i < 0 {
		return "", "", nil, errors.New("'Protection: ' not found in " + constants.SeedFilename)
	}
	clearAndTrim(content, i+len([]byte("Protection: ")))
	i = bytes.Index(*content, []byte("\n"))
	if i < 0 {
		return "", "", nil, errors.New("New line not found after 'Protection: ' in " + constants.SeedFilename)
	}
	protection = string((*content)[:i])
	clearAndTrim(content, i+len([]byte("\n")))
	i = bytes.Index(*content, []byte("Secret Seed: "))
	if i < 0 {
		return "", "", nil, errors.New("'Secret Seed: ' not found in " + constants.SeedFilename)
	}
	clearAndTrim(content, i+len([]byte("Secret Seed: ")))
	seed = new([]byte)
	*seed, err = base64.StdEncoding.DecodeString(string(*content))
	ClearByteSlice(content)
	if err != nil {
		return "", "", nil, err
	}
	return defaultUser, protection, seed, nil
}
