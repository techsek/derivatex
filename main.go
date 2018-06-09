package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"

	"github.com/fatih/color"
	ps "github.com/nbutton23/zxcvbn-go"
)

var argonTimeNs int64

func main() {
	createCommand := flag.NewFlagSet("create", flag.ExitOnError)
	generateCommand := flag.NewFlagSet("generate", flag.ExitOnError)
	passwordLengthPtr := generateCommand.Int("length", 20, "Length of the derived password")
	if len(os.Args) < 2 {
		fmt.Println("create or generate command is required")
		os.Exit(1)
	}
	if os.Args[1] == "create" {
		createCommand.Parse(os.Args[2:])
	} else if os.Args[1] == "generate" {
		generateCommand.Parse(os.Args[2:])
	} else {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if createCommand.Parsed() {
		create()
	}
	if generateCommand.Parsed() {
		if len(os.Args) < 3 {
			fmt.Println("Website name is missing after command generate")
			os.Exit(1)
		}
		website := os.Args[2]
		generate(website, *passwordLengthPtr)
	}
}

func generate(website string, passwordLength int) {
	masterDigest, err := readMasterDigest()
	if err != nil {
		color.Yellow("An error occurred reading the master digest file: " + err.Error())
		return
	}
	if (*masterDigest)[len((*masterDigest))-1] == 1 { // encrypted with PIN code
		*masterDigest = (*masterDigest)[:len((*masterDigest))-1]
		var pinCodeSHA3 *[32]byte
		for {
			pinCode, err := readSecret("Enter your PIN code to decrypt the master digest: ")
			if err != nil {
				color.Yellow("An error occurred reading the PIN code: " + err.Error())
				continue
			}
			valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
			if !valid {
				color.Yellow("The PIN code you entered is not valid.")
				clearByteSlice(pinCode)
				continue
			}
			pinCodeSHA3 = hashAndDestroy(pinCode)
			masterDigest, err = decryptAES(masterDigest, pinCodeSHA3)
			if err != nil {
				color.HiRed("The following error occurred when decrypting the master digest: " + err.Error())
				continue
			}
			err = dechecksumize(masterDigest)
			if err != nil {
				color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
				continue
			}
			break
		}
	}

	password := determinePassword(masterDigest, []byte(website), passwordLength)
	fmt.Println(color.HiGreenString("Your password for "+string(website)+" is: ") + color.HiWhiteString(password))
}

func create() {
	color.HiWhite("Detecting performance of machine for Argon2ID...")
	argonTimeNs = getArgonTime() // depends on the machine
	color.HiGreen("%d miliseconds per Argon time cost", argonTimeNs/1000000)
	var masterPasswordSHA3, birthdateSHA3, pinCodeSHA3 *[32]byte
	for {
		for {
			masterPassword, err := readSecret("Enter your master password: ")
			if err != nil {
				color.Yellow("An error occurred reading the password: " + err.Error())
				continue
			}
			safety, message := evaluatePassword(masterPassword)
			masterPasswordSHA3 = hashAndDestroy(masterPassword)
			color.HiWhite(message)
			if safety == 0 {
				color.Yellow("Your password is not safe, please enter a more complicated password.")
				continue
			} else if safety == 1 {
				setStrongerPassword := readInput("Your password is not very safe, would you like to enter a stronger password? (yes/no) [no]: ")
				if setStrongerPassword == "yes" {
					clearByteArray32(masterPasswordSHA3)
					continue
				}
			} else {
				color.HiGreen("Your password is very safe, good job!")
			}
			masterPasswordConfirm, err := readSecret("Enter your master password again: ")
			if err != nil {
				color.Yellow("An error occurred reading the password confirmation: " + err.Error())
				continue
			}
			masterPasswordSHA3Confirm := hashAndDestroy(masterPasswordConfirm)
			if !byteArrays32Equal(masterPasswordSHA3, masterPasswordSHA3Confirm) {
				color.Yellow("The passwords entered do not match, please try again.")
				clearByteArray32(masterPasswordSHA3)
				clearByteArray32(masterPasswordSHA3Confirm)
				continue
			}
			clearByteArray32(masterPasswordSHA3Confirm)
			break
		}
		for {
			birthdate, err := readSecret("Enter your date of birth in the format dd/mm/yyyy: ")
			if err != nil {
				color.Yellow("An error occurred reading your birthdate: " + err.Error())
				continue
			}
			if !dateIsValid(birthdate) {
				color.Yellow("The birthdate you entered is not valid.")
				clearByteSlice(birthdate)
				continue
			}
			birthdateSHA3 = hashAndDestroy(birthdate)
			birthdateConfirm, err := readSecret("Enter your date of birth in the format dd/mm/yyyy again: ")
			if err != nil {
				color.Yellow("An error occurred reading your birthdate confirmation: " + err.Error())
				clearByteArray32(birthdateSHA3)
				continue
			}
			birthdateSHA3Confirm := hashAndDestroy(birthdateConfirm)
			if !byteArrays32Equal(birthdateSHA3, birthdateSHA3Confirm) {
				color.Yellow("The birthdates entered do not match, please try again.")
				clearByteArray32(birthdateSHA3)
				clearByteArray32(birthdateSHA3Confirm)
				continue
			}
			color.HiGreen("Your birthdate is valid.")
			break
		}
		color.HiWhite("Computing master digest...")
		go showHashProgress(argonTimeCost)
		masterDigest := createMasterDigest(masterPasswordSHA3, birthdateSHA3, argonTimeCost)
		clearByteArray32(masterPasswordSHA3)
		clearByteArray32(birthdateSHA3)
		color.HiGreen("\nMaster digest computed successfully")
		optionPin := readInput("[OPTIONAL] To generate a password, would you like to setup a 4 digit pin code? (yes/no) [no]: ")
		if optionPin == "yes" {
			for {
				pinCode, err := readSecret("Please choose your PIN code in the format 9999: ")
				if err != nil {
					color.Yellow("An error occurred reading the PIN code: " + err.Error())
					continue
				}
				valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
				if !valid {
					color.Yellow("The PIN code you entered is not valid.")
					clearByteSlice(pinCode)
					continue
				}
				pinCodeSHA3 = hashAndDestroy(pinCode)
				pinCodeConfirm, err := readSecret("Please confirm your PIN code in the format 9999: ")
				if err != nil {
					color.Yellow("An error occurred reading the PIN code confirmation: " + err.Error())
					continue
				}
				pinCodeSHA3Confirm := hashAndDestroy(pinCodeConfirm)
				if !byteArrays32Equal(pinCodeSHA3, pinCodeSHA3Confirm) {
					color.Yellow("The PIN codes entered do not match, please try again.")
					clearByteArray32(pinCodeSHA3)
					clearByteArray32(pinCodeSHA3Confirm)
					continue
				}
				checksumize(masterDigest)
				masterDigest, err = encryptAES(masterDigest, pinCodeSHA3)
				if err != nil {
					color.HiRed("The following error occurred when encrypting the master digest: " + err.Error())
					continue
				}
				clearByteArray32(pinCodeSHA3)
				*masterDigest = append(*masterDigest, byte(1)) // 1 means encrypted with PIN code
				color.HiGreen("\nMaster digest encrypted using PIN code successfully")
				break
			}
		} else {
			*masterDigest = append(*masterDigest, byte(0)) // not encrypted with PIN code
		}
		// TODO Yubikey with https://github.com/tstranex/u2f
		err := writeMasterDigest(masterDigest)
		clearByteSlice(masterDigest)
		if err != nil {
			color.HiRed("Error writing master digest to file: " + err.Error())
			continue
		}
		color.HiGreen("Master digest saved successfully!")
		break
	}
}

func displayTime(seconds float64) string {
	formater := "%.1f %s"
	minute := float64(60)
	hour := minute * float64(60)
	day := hour * float64(24)
	month := day * float64(31)
	year := month * float64(12)
	century := year * float64(100)

	if seconds < minute {
		return "a few seconds"
	} else if seconds < hour {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/minute)), "minutes")
	} else if seconds < day {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/hour)), "hours")
	} else if seconds < month {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/day)), "days")
	} else if seconds < year {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/month)), "months")
	} else if seconds < century {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/century)), "years")
	} else {
		return "centuries"
	}
}

func evaluatePassword(masterPassword *[]byte) (safety uint8, message string) {
	analysis := ps.PasswordStrength(string(*masterPassword), []string{})
	// TODO find cracktime
	message = "Your password has an entropy of " + strconv.FormatFloat(analysis.Entropy, 'f', 2, 64) + " bits, equivalent to a suitcase lock of " + strconv.FormatFloat(analysis.Entropy*0.30103, 'f', 0, 64) + " digits."
	if analysis.Entropy > 30 {
		safety = 1
	}
	if analysis.Entropy > 50 {
		safety = 2
	}
	return safety, message
}

func bytes32ToUint32(b *[32]byte) (n *uint32) {
	n = new(uint32)
	*n = binary.LittleEndian.Uint32((*b)[:])
	return n
}
