package cmd

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/mdp/qrterminal"
	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

type generateParams struct {
	passwordLength            int
	user                      string
	round                     int
	note                      string
	excludedCharacters        string
	noSymbol                  bool
	noDigit                   bool
	noUppercase               bool
	noLowercase               bool
	pinCode                   string
	qrcode                    bool
	clipboard                 bool
	passwordOnly              bool
	save                      bool
	passwordDerivationVersion int
}

var generateP generateParams

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().IntVar(&generateP.passwordLength, "length", constants.DefaultPasswordLength, "Length of the derived password")
	generateCmd.Flags().StringVar(&generateP.user, "user", "", "Email, username or phone number the password is to be used with")
	generateCmd.Flags().IntVar(&generateP.round, "round", 1, "Make higher than 1 if the password has to be renewed for the website")
	generateCmd.Flags().BoolVar(&generateP.noSymbol, "nosymbol", false, "Force the password to contain no symbol")
	generateCmd.Flags().BoolVar(&generateP.noDigit, "nodigit", false, "Force the password to contain no digit")
	generateCmd.Flags().BoolVar(&generateP.noUppercase, "nouppercase", false, "Force the password to contain no uppercase letter")
	generateCmd.Flags().BoolVar(&generateP.noLowercase, "nolowercase", false, "Force the password to contain no lowercase letter")
	generateCmd.Flags().StringVar(&generateP.excludedCharacters, "exclude", "", "Characters to exclude from the final password")
	generateCmd.Flags().StringVar(&generateP.note, "note", "", "Extra personal note you want to add")
	generateCmd.Flags().StringVar(&generateP.pinCode, "pin", "", "4 digits pin code in case the secret digest is encrypted")
	generateCmd.Flags().BoolVar(&generateP.qrcode, "qr", true, "Display the resulting password as a QR code")
	generateCmd.Flags().BoolVar(&generateP.clipboard, "clipboard", true, "Copy the resulting password to the clipboard")
	generateCmd.Flags().BoolVar(&generateP.passwordOnly, "passwordonly", false, "Only display the resulting password (for piping)")
	generateCmd.Flags().BoolVar(&generateP.save, "save", true, "Save the password generation settings and corresponding user to the database")
	generateCmd.Flags().IntVar(&generateP.passwordDerivationVersion, "version", constants.PasswordDerivationVersion, "Version of the core password generation code to be used")
}

var generateCmd = &cobra.Command{
	Use:   "generate <websitename>",
	Short: "Create the master digest",
	Long: `Create the master password digest. By default this runs interactively
as it is safer since commands are saved in bash history.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		website := args[0]
		unallowedCharacters := internal.BuildUnallowedCharacters(generateP.noSymbol, generateP.noDigit, generateP.noUppercase, generateP.noLowercase, generateP.excludedCharacters)
		if !unallowedCharacters.IsAnythingAllowed() {
			color.HiRed("The password can't be generated with all possible characters excluded")
			return
		}
		defaultUser, protection, seed, err := internal.ReadSeed()
		if err != nil {
			color.Yellow("An error occurred reading the master digest file: " + err.Error())
			return
		}
		if protection == "pin" && generateP.pinCode != "" { // pinCode provided as argument
			pinCodeBytes := []byte(generateP.pinCode)
			pinCode := &pinCodeBytes
			valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
			if !valid {
				internal.ClearByteSlice(pinCode)
				color.HiRed("The PIN code you entered is not in the valid format.")
				return
			}
			var pinCodeSHA3 = internal.HashAndDestroy(pinCode)
			decryptedSeed, err := internal.DecryptAES(seed, pinCodeSHA3)
			internal.ClearByteArray32(pinCodeSHA3)
			if err != nil {
				internal.ClearByteSlice(decryptedSeed)
				color.HiRed("Decryption error: " + err.Error())
				return
			}
			err = internal.Dechecksumize(decryptedSeed)
			if err != nil {
				internal.ClearByteSlice(decryptedSeed)
				color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
				return
			}
			internal.ClearByteSlice(seed)
			seed = decryptedSeed
		}

		user := defaultUser
		if generateP.user != "" { // user flag provided
			user = generateP.user
		}

		newIdentification := internal.IdentificationType{
			Website:                   website,
			User:                      user,
			PasswordLength:            uint8(generateP.passwordLength),
			Round:                     uint16(generateP.round),
			UnallowedCharacters:       unallowedCharacters.Serialize(),
			CreationTime:              time.Now().Unix(), // set to previous database record if a record is found
			PasswordDerivationVersion: uint16(generateP.passwordDerivationVersion),
			Note: generateP.note,
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
						internal.DisplayIdentificationCLI(identifications[i])
						color.HiWhite("You are trying to create a password with the following identification:")
						internal.DisplayIdentificationCLI(newIdentification)
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
				if len(identifications) == 1 && newIdentification.IsDefault(user == "") { // lazy generating
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
		if protection == "pin" && generateP.pinCode == "" {
			var pinCodeSHA3 *[32]byte
			var decryptedSeed *[]byte
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
				decryptedSeed, err = internal.DecryptAES(seed, pinCodeSHA3)
				internal.ClearByteArray32(pinCodeSHA3)
				if err != nil {
					internal.ClearByteSlice(decryptedSeed)
					color.HiRed("Decryption error: " + err.Error())
					continue
				}
				err = internal.Dechecksumize(decryptedSeed)
				if err != nil {
					internal.ClearByteSlice(decryptedSeed)
					color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
					continue
				}
				internal.ClearByteSlice(seed)
				seed = decryptedSeed
				break
			}
		}
		generateP.pinCode = ""

		var password string
		if newIdentification.PasswordDerivationVersion == 1 {
			password = internal.DeterminePassword(seed, []byte(website), []byte{}, newIdentification.PasswordLength, newIdentification.Round, unallowedCharacters)
		} else {
			password = internal.DeterminePassword(seed, []byte(website), []byte(user), newIdentification.PasswordLength, newIdentification.Round, unallowedCharacters)
		}

		if generateP.save {
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
		if generateP.passwordOnly {
			fmt.Print(password)
			return
		}
		if generateP.qrcode {
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
		if generateP.clipboard {
			clipboard.WriteAll(password)
			color.HiGreen("Password copied to clipboard")
		}
	},
}
