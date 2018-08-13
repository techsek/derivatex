package commands

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/mdp/qrterminal"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

var generateFlagSet = flag.NewFlagSet("generate", flag.ExitOnError)

func Generate(args []string) {
	var generateParams struct {
		passwordLength                              int
		user                                        string
		round                                       int
		note                                        string
		excludedCharacters                          string
		noSymbol, noDigit, noUppercase, noLowercase bool
		pinCode                                     string
		qrcode                                      bool
		clipboard                                   bool
		passwordOnly                                bool
		save                                        bool
		programVersion                              int
	}
	generateFlagSet.IntVar(&generateParams.passwordLength, "length", constants.DefaultPasswordLength, "Length of the derived password")
	generateFlagSet.StringVar(&generateParams.user, "user", "", "Email, username or phone number the password is to be used with")
	generateFlagSet.IntVar(&generateParams.round, "round", 1, "Make higher than 1 if the password has to be renewed for the website")
	generateFlagSet.BoolVar(&generateParams.noSymbol, "nosymbol", false, "Force the password to contain no symbol")
	generateFlagSet.BoolVar(&generateParams.noDigit, "nodigit", false, "Force the password to contain no digit")
	generateFlagSet.BoolVar(&generateParams.noUppercase, "nouppercase", false, "Force the password to contain no uppercase letter")
	generateFlagSet.BoolVar(&generateParams.noLowercase, "nolowercase", false, "Force the password to contain no lowercase letter")
	generateFlagSet.StringVar(&generateParams.excludedCharacters, "exclude", "", "Characters to exclude from the final password")
	generateFlagSet.StringVar(&generateParams.note, "note", "", "Extra personal note you want to add")
	generateFlagSet.StringVar(&generateParams.pinCode, "pin", "", "4 digits pin code in case the secret digest is encrypted")
	generateFlagSet.BoolVar(&generateParams.qrcode, "qr", true, "Display the resulting password as a QR code")
	generateFlagSet.BoolVar(&generateParams.clipboard, "clipboard", true, "Copy the resulting password to the clipboard")
	generateFlagSet.BoolVar(&generateParams.passwordOnly, "passwordonly", false, "Only display the resulting password (for piping)")
	generateFlagSet.BoolVar(&generateParams.save, "save", true, "Save the password generation settings and corresponding user to the database")
	generateFlagSet.IntVar(&generateParams.programVersion, "version", constants.Version, "Version of the core password generation code to be used")
	generateFlagSet.Parse(args[2:])
	if generateFlagSet.Parsed() {
		generateCLI(args[1], &generateParams)
	}
}

func generateCLI(website string, params *struct {
	passwordLength     int
	user               string
	round              int
	note               string
	excludedCharacters string
	noSymbol           bool
	noDigit            bool
	noUppercase        bool
	noLowercase        bool
	pinCode            string
	qrcode             bool
	clipboard          bool
	passwordOnly       bool
	save               bool
	programVersion     int
}) {
	unallowedCharacters := internal.BuildUnallowedCharacters(params.noSymbol, params.noDigit, params.noUppercase, params.noLowercase, params.excludedCharacters)
	if !unallowedCharacters.IsAnythingAllowed() {
		color.HiRed("The password can't be generated with all possible characters excluded")
		return
	}
	defaultUser, protection, masterDigest, err := internal.ReadMasterDigest()
	if err != nil {
		color.Yellow("An error occurred reading the master digest file: " + err.Error())
		return
	}
	if protection == "pin" && params.pinCode != "" { // pinCode provided as argument
		pinCodeBytes := []byte(params.pinCode)
		pinCode := &pinCodeBytes
		valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
		if !valid {
			internal.ClearByteSlice(pinCode)
			color.HiRed("The PIN code you entered is not in the valid format.")
			return
		}
		var pinCodeSHA3 = internal.HashAndDestroy(pinCode)
		decryptedMasterDigest, err := internal.DecryptAES(masterDigest, pinCodeSHA3)
		internal.ClearByteArray32(pinCodeSHA3)
		if err != nil {
			internal.ClearByteSlice(decryptedMasterDigest)
			color.HiRed("Decryption error: " + err.Error())
			return
		}
		err = internal.Dechecksumize(decryptedMasterDigest)
		if err != nil {
			internal.ClearByteSlice(decryptedMasterDigest)
			color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
			return
		}
		internal.ClearByteSlice(masterDigest)
		masterDigest = decryptedMasterDigest
	}

	user := defaultUser
	if params.user != "" { // user flag provided
		user = params.user
	}

	newIdentification := internal.IdentificationType{
		Website:             website,
		User:                user,
		PasswordLength:      uint8(params.passwordLength),
		Round:               uint16(params.round),
		UnallowedCharacters: unallowedCharacters.Serialize(),
		CreationTime:        time.Now().Unix(), // set to previous database record if a record is found
		ProgramVersion:      uint16(params.programVersion),
		Note:                params.note,
	}
	identifications, err := internal.FindIdentificationsByWebsite(website)
	if err != nil {
		color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
		return
	}
	var replaceIdentification bool
	if len(identifications) > 0 {
		var identificationExists bool
		for i := range identifications {
			if newIdentification.User == identifications[i].User { // identification already exists in database
				identificationExists = true
				if identifications[i].GenerationParamsEqualTo(&newIdentification) {
					newIdentification.CreationTime = identifications[i].CreationTime
				} else {
					color.HiWhite("A password for the following identification has already been generated previously:")
					color.White(strings.Join(internal.IdentificationTypeLegendStrings(), " | "))
					color.White(strings.Join(identifications[i].ToStrings(), " | "))
					color.HiWhite("You are trying to create a password with the following identification:")
					color.White(strings.Join(internal.IdentificationTypeLegendStrings(), " | "))
					color.White(strings.Join(newIdentification.ToStrings(), " | "))
					for {
						replaceOrOld := internal.ReadInput("Replace the old identification or generate using the old identification? (replace/old) [old]: ")
						if replaceOrOld == "replace" {
							replaceIdentification = true
							break
						} else if replaceOrOld == "old" || replaceOrOld == "" {
							newIdentification = identifications[i]
							break
						}
						color.Yellow("Choice '" + replaceOrOld + "' is not a valid. Please try again")
					}
				}
				break
			}
		}
		if !identificationExists {
			if len(identifications) == 1 && newIdentification.IsDefault(params.user == "") { // lazy generating
				color.Yellow("This password is assumed to be generated for user '" + identifications[0].User + "' using the corresponding stored settings.")
				newIdentification = identifications[0]
			} else {
				color.HiWhite("Password(s) for the following identification(s) have already been generated previously:")
				internal.DisplayIdentificationsCLI(identifications)
				for {
					continueGenerate := internal.ReadInput("Generate a password for '" + website + "' and new user '" + user + "'? (yes/no) [no]: ")
					if continueGenerate == "yes" {
						break
					} else if continueGenerate == "no" || continueGenerate == "" {
						return
					}
					color.Yellow("Choice '" + continueGenerate + "' is not a valid. Please try again")
				}
			}
		}
	}
	if protection == "pin" && params.pinCode == "" {
		var pinCodeSHA3 *[32]byte
		var decryptedMasterDigest *[]byte
		for {
			pinCode, err := internal.ReadSecret("Enter your PIN code to decrypt the master digest: ")
			if err != nil {
				color.Yellow("An error occurred reading the PIN code: " + err.Error())
				continue
			}
			valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
			if !valid {
				internal.ClearByteSlice(pinCode)
				color.Yellow("The PIN code you entered is not in the valid format.")
				continue
			}
			pinCodeSHA3 = internal.HashAndDestroy(pinCode)
			decryptedMasterDigest, err = internal.DecryptAES(masterDigest, pinCodeSHA3)
			internal.ClearByteArray32(pinCodeSHA3)
			if err != nil {
				internal.ClearByteSlice(decryptedMasterDigest)
				color.HiRed("Decryption error: " + err.Error())
				continue
			}
			err = internal.Dechecksumize(decryptedMasterDigest)
			if err != nil {
				internal.ClearByteSlice(decryptedMasterDigest)
				color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
				continue
			}
			internal.ClearByteSlice(masterDigest)
			masterDigest = decryptedMasterDigest
			break
		}
	}
	params.pinCode = ""

	var password string
	if newIdentification.ProgramVersion == 1 {
		password = internal.DeterminePassword(masterDigest, []byte(website), []byte{}, newIdentification.PasswordLength, newIdentification.Round, unallowedCharacters)
	} else {
		password = internal.DeterminePassword(masterDigest, []byte(website), []byte(user), newIdentification.PasswordLength, newIdentification.Round, unallowedCharacters)
	}

	if params.save {
		// TODO transaction
		if replaceIdentification {
			err := internal.DeleteIdentification(newIdentification.Website, newIdentification.User)
			if err != nil {
				color.HiRed("Error deleting the identification: " + err.Error())
				return
			}
		}
		internal.InsertIdentification(newIdentification)
	}
	if params.passwordOnly {
		fmt.Print(password)
		return
	}
	if params.qrcode {
		color.HiGreen("Password QR Code:")
		config := qrterminal.Config{
			Level:     qrterminal.M,
			Writer:    os.Stdout,
			BlackChar: qrterminal.WHITE,
			WhiteChar: qrterminal.BLACK,
			QuietZone: 1,
		}
		qrterminal.GenerateWithConfig(password, config)
	}
	fmt.Println(color.HiGreenString("User: ") + color.HiWhiteString(newIdentification.User))
	fmt.Println(color.HiGreenString("Password: ") + color.HiWhiteString(password))
	if params.clipboard {
		clipboard.WriteAll(password)
		color.HiGreen("Password copied to clipboard")
	}
}
