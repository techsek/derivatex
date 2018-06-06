package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"syscall"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"
)

var argonTimeNs int64

func main() {
	argonTimeNs = getArgonTime() // depends on the machine
	create()
}

func readInput(prompt string) (input []byte) {
	promptColor := color.HiMagentaString(prompt)
	fmt.Print(promptColor)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		input = scanner.Bytes()
	}
	return input
}

func readPassword(prompt string) (password []byte, err error) {
	promptColor := color.HiMagentaString(prompt)
	fmt.Print(promptColor)
	password, err = terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	return password, nil
}

func create() {
	var masterPassword, masterPasswordConfirm, birthdate, birthdateConfirm, pinCode, pinCodeConfirm, encryptionKey []byte
	var err error
	for {
		for {
			masterPassword, err = readPassword("Enter your master password: ")
			if err != nil {
				color.HiYellow("An error occurred reading the password: " + err.Error())
				continue
			}
			masterPasswordConfirm, err = readPassword("Enter your master password again: ")
			if err != nil {
				color.HiYellow("An error occurred reading the password confirmation: " + err.Error())
				continue
			}
			if !reflect.DeepEqual(masterPassword, masterPasswordConfirm) {
				color.HiYellow("The passwords entered do not match, please try again.")
				continue
			}
			masterPasswordConfirm = nil // TODO clear better with pointers etc.
			safety, message := evaluatePassword(&masterPassword)
			color.HiWhite(message)
			if safety == 0 {
				color.HiYellow("Your password is not safe, please enter a more complicated password.")
				continue
			} else if safety == 1 {
				newPassword := readInput("Your password is not very safe, would you like to enter a stronger password? (yes/no) [no]: ")
				if string(newPassword) == "yes" {
					continue
				}
			} else {
				color.HiGreen("Your password is very safe, good job!")
				break
			}
		}
		for {
			birthdate, err = readPassword("Enter your date of birth in the format dd/mm/yyyy: ")
			if err != nil {
				color.HiYellow("An error occurred reading your birthdate: " + err.Error())
				continue
			}
			if !dateIsValid(string(birthdate)) {
				color.HiYellow("The birthdate you entered is not valid.")
				continue
			}
			birthdateConfirm, err = readPassword("Enter your date of birth in the format dd/mm/yyyy again: ")
			if err != nil {
				color.HiYellow("An error occurred reading your birthdate confirmation: " + err.Error())
				continue
			}
			if !reflect.DeepEqual(birthdate, birthdateConfirm) {
				color.HiYellow("The birthdates entered do not match, please try again.")
				continue
			}
			birthdateConfirm = nil // TODO clear better with pointers etc.
			color.HiGreen("Your birthdate is valid!")
			break
		}
		color.White("Computing master digest...")
		argonTimeCost := determineArgonTimeCost(birthdate)
		go showHashProgress(int(argonTimeCost))
		masterDigest := createMasterDigest(&masterPassword, &birthdate, argonTimeCost)
		color.HiGreen("\nMaster digest computed successfully")
		optionPin := readInput("[OPTIONAL] To generate a password, would you like to setup a 4 digit pin code? (yes/no) [no]: ")
		if string(optionPin) == "yes" {
			for {
				pinCode, err = readPassword("Please choose your PIN code in the format 9999: ")
				if err != nil {
					color.HiYellow("An error occurred reading the PIN code: " + err.Error())
					continue
				}
				valid, _ := regexp.MatchString("^[0-9]{4}$", string(pinCode))
				if !valid {
					color.HiYellow("The PIN code you entered is not valid.")
					continue
				}
				pinCodeConfirm, err = readPassword("Please confirm your PIN code in the format 9999: ")
				if err != nil {
					color.HiYellow("An error occurred reading the PIN code confirmation: " + err.Error())
					continue
				}
				if !reflect.DeepEqual(pinCode, pinCodeConfirm) {
					color.HiYellow("The PIN codes entered do not match, please try again.")
					continue
				}
				encryptionKey = hashAndDestroy(&pinCode)
				checksumize(&masterDigest)
				masterDigest, err = encryptAES(masterDigest, encryptionKey)
				encryptionKey = nil                          // TODO
				masterDigest = append(masterDigest, byte(1)) // 1 means encrypted with pin code
				break
			}
		} else {
			masterDigest = append(masterDigest, byte(0)) // not encrypted at all
		}
		// TODO Yubikey with https://github.com/tstranex/u2f
		err := ioutil.WriteFile("MasterPasswordDigest", masterDigest, 0644)
		masterDigest = nil // TODO
		if err != nil {
			color.HiRed("Error writing master digest to file: " + err.Error())
			continue
		}
		color.HiGreen("Master digest saved successfully!")
		break
	}
}
