package cmd

import (
	"fmt"
	"os"
	"strconv"
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
	generateCmd.Flags().BoolVar(&generateP.qrcode, "qr", true, "Display the resulting password as a QR code")
	generateCmd.Flags().BoolVar(&generateP.clipboard, "clipboard", true, "Copy the resulting password to the clipboard")
	generateCmd.Flags().BoolVar(&generateP.passwordOnly, "passwordonly", false, "Only display the resulting password (for piping)")
	generateCmd.Flags().BoolVar(&generateP.save, "save", true, "Save the password generation settings and corresponding user to the database")
	generateCmd.Flags().IntVar(&generateP.passwordDerivationVersion, "version", constants.PasswordDerivationVersion, "Version of the core password generation code to be used")
}

var generateCmd = &cobra.Command{
	Use:   "generate <websitename>",
	Short: "Generate a password using the seed",
	Long:  `Generate a password for a particular website and user using the seed`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		website := args[0]
		unallowedCharacters := internal.BuildUnallowedCharacters(generateP.noSymbol, generateP.noDigit, generateP.noUppercase, generateP.noLowercase, generateP.excludedCharacters)
		if !unallowedCharacters.IsAnythingAllowed() {
			color.HiRed("The password can't be generated with all possible characters excluded")
			return
		}
		defaultUser, protection, seed, err := internal.ReadSeed()
		if err != nil {
			color.Yellow("An error occurred reading the seed file: " + err.Error())
			return
		}

		userIsDefault := true
		user := defaultUser
		if generateP.user != "" { // user flag provided
			user = generateP.user
			userIsDefault = false
		}

		if protection == "passphrase" { // TODO encrypt/decrypt SQLite
			for {
				passphraseBytesPtr, err := internal.ReadSecret("Enter your passphrase to decrypt the seed: ")
				if err != nil {
					color.Yellow("An error occurred reading the passphrase: " + err.Error())
					continue
				}
				decryptedSeed, err := internal.DecryptSeed(seed, passphraseBytesPtr)
				internal.ClearByteSlice(passphraseBytesPtr)
				if err != nil {
					internal.ClearByteSlice(decryptedSeed)
					color.HiRed("Seed or passphrase is invalid: " + err.Error())
					continue
				}
				internal.ClearByteSlice(seed)
				seed = decryptedSeed
				break
			}
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
		identificationIsNew := true
		identificationExists := false
		replaceIdentification := false
		identifications, err := internal.FindIdentificationsByWebsite(website)
		if err != nil {
			color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
			return
		}

		if len(identifications) == 0 {
			identificationIsNew = true
		} else if len(identifications) == 1 {
			existingIdentification := identifications[0]
			if newIdentification.User == existingIdentification.User {
				identificationExists = true
				if newIdentification.GenerationParamsEqualTo(&existingIdentification) {
					newIdentification.CreationTime = existingIdentification.CreationTime
					newIdentification.Note = existingIdentification.Note // TODO
					identificationIsNew = false
				} else {
					color.HiWhite("A password for the following identification has already been generated previously:")
					internal.DisplayIdentificationCLI(existingIdentification)
					color.HiWhite("You are trying to create a password with the following settings:")
					internal.DisplayIdentificationCLI(newIdentification)
					for {
						replaceOrOld := internal.ReadInput("Replace the old identification or generate using the old identification? (replace/old) [old]: ")
						if replaceOrOld == "replace" {
							replaceIdentification = true
							identificationIsNew = true
							break
						} else if replaceOrOld == "old" || replaceOrOld == "" {
							newIdentification = existingIdentification
							identificationIsNew = false
							break
						}
						color.Yellow("Choice '" + replaceOrOld + "' is not valid. Please try again")
					}
				}
			}
			if !identificationExists && newIdentification.HasDefaultParams(userIsDefault) { // lazy generating
				newIdentification = identifications[0]
				identificationIsNew = false
				color.Yellow("This password is assumed to be generated using the following stored settings:")
				internal.DisplayIdentificationCLI(newIdentification)
				color.White("Please add flags to overwrite this default generation.")
			}
		} else {
			var existingIdentification internal.IdentificationType
			for _, existingIdentification = range identifications {
				if newIdentification.User == existingIdentification.User {
					identificationExists = true
					if newIdentification.GenerationParamsEqualTo(&existingIdentification) {
						newIdentification.CreationTime = existingIdentification.CreationTime
						newIdentification.Note = existingIdentification.Note // TODO
						identificationIsNew = false
					}
					break
				}
			}
			if identificationExists && identificationIsNew { // new generation parameters
				color.HiWhite("A password for the following identification has already been generated previously:")
				internal.DisplayIdentificationCLI(existingIdentification)
				color.HiWhite("You are trying to create a password with the following settings:")
				internal.DisplayIdentificationCLI(newIdentification)
				for {
					replaceOrOld := internal.ReadInput("Replace the old identification or generate using the old identification? (replace/old) [old]: ")
					if replaceOrOld == "replace" {
						replaceIdentification = true
						identificationIsNew = true
						break
					} else if replaceOrOld == "old" || replaceOrOld == "" {
						newIdentification = existingIdentification
						identificationIsNew = false
						break
					}
					color.Yellow("Choice '" + replaceOrOld + "' is not valid. Please try again")
				}
			} else if !identificationExists { // did not find it previously
				color.HiWhite("Passwords for the following identifications have already been generated previously:")
				internal.DisplayIdentificationsCLI(identifications)
				for {
					newOrOld := internal.ReadInput("Generate a password for '" + website + "' and new user '" + user + "' or use one of the old stored settings? (new/old) [old]: ")
					if newOrOld == "new" {
						break
					} else if newOrOld == "old" || newOrOld == "" {
						identificationIsNew = false
						color.White("Please enter one of the following users to choose the corresponding password generation settings:")
						existingUsers := internal.ExtractUsers(identifications)
						internal.DisplaySingleColumnCLI("USER", existingUsers)
						for {
							chosenUser := internal.ReadInput("User [" + existingUsers[0] + "]: ")
							if chosenUser == "" {
								chosenUser = existingUsers[0]
							}
							for _, identification := range identifications {
								if chosenUser == identification.User {
									newIdentification = identification
									break
								}
							}
							color.Yellow("User '" + chosenUser + "' is not valid. Please try again")
						}
					}
					color.Yellow("Choice '" + newOrOld + "' is not valid. Please try again")
				}
			}
		}

		if newIdentification.PasswordDerivationVersion != constants.PasswordDerivationVersion {
			color.HiYellow("This password is generated using the derivation program version " + strconv.FormatUint(uint64(newIdentification.PasswordDerivationVersion), 10) + ", you should change it using the latest version " + strconv.FormatUint(uint64(constants.PasswordDerivationVersion), 10) + " of the current program")
		}

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
			if identificationIsNew {
				color.HiGreen("Saving new identification and password generation settings in database:")
				internal.DisplayIdentificationCLI(newIdentification)
				internal.InsertIdentification(newIdentification)
			}
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
