package cmd

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"

	"github.com/fatih/color"
	ps "github.com/nbutton23/zxcvbn-go"
	pb "gopkg.in/cheggaaa/pb.v1"
)

type createParams struct {
	masterPassword string
	birthdate      string
	defaultUser    string
	pinCode        string
}

var createP createParams

func init() {
	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVar(&createP.masterPassword, "password", "", "Master password to be used to generate the digest file (you should not use this flag for better security)")
	createCmd.Flags().StringVar(&createP.birthdate, "birthdate", "", "Your birthdate in the format dd/mm/yyyy (you should not use this flag for better security)")
	createCmd.Flags().StringVar(&createP.defaultUser, "user", "", "Your default user to be used when generating passwords without specifying a particular user")
	createCmd.Flags().StringVar(&createP.pinCode, "pin", "", "An optional 4 digit code to encrypt your digest file (you should not use this flag for better security)")
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create the master digest.",
	Long: `Create the master password digest. By default this runs interactively
as it is safer since commands are saved in bash history.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(color.HiWhiteString("Detecting performance of machine for Argon2ID..."))
		argonTimePerRound := internal.GetArgonTimePerRound()              // depends on the machine
		fmt.Println(color.HiGreenString("%dms/round", argonTimePerRound)) // TODO in goroutine

		var masterPasswordSHA3, birthdateSHA3, pinCodeSHA3 *[32]byte
		var user string
		var protection = "none"
		if createP.masterPassword != "" { // master password provided in argument
			color.Yellow("Your password was provided as a command line flag, but it is safer to provide it within the interactive command line interface of derivatex.")
			masterPassword := []byte(createP.masterPassword)
			safety, message := evaluatePassword(&masterPassword)
			masterPasswordSHA3 = internal.HashAndDestroy(&masterPassword)
			color.HiWhite(message)
			if safety == 0 {
				internal.ClearByteArray32(masterPasswordSHA3)
				color.HiRed("Your password is not safe, please enter a more complicated password.")
				return
			} else if safety == 1 {
				color.Yellow("Your password is not very safe, you might want to abort (CTRL + C) and use a stronger password")
			}
		}
		if createP.birthdate != "" { // birthdate provided in argument
			color.Yellow("Your birthdate was provided as a command line flag, but it is safer to provide it within the interactive command line interface of derivatex.")
			birthdateBytes := []byte(createP.birthdate)
			var birthdate = &birthdateBytes
			if !dateIsValid(birthdate) {
				color.HiRed("The birthdate you entered is not valid.")
				internal.ClearByteSlice(birthdate)
				return
			}
			birthdateSHA3 = internal.HashAndDestroy(birthdate)
		}
		if createP.pinCode != "" { // pin code provided in argument
			color.Yellow("Your encryption 4 digit code was provided as a command line flag, but it is safer to provide it within the interactive command line interface of Derivatex.")
			pinCodeBytes := []byte(createP.pinCode)
			pinCode := &pinCodeBytes
			protection = "pin"
			valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
			if !valid {
				internal.ClearByteSlice(pinCode)
				color.HiRed("Your 4 digit code is not valid.")
				return
			}
			pinCodeSHA3 = internal.HashAndDestroy(pinCode)
		}

		if createP.masterPassword == "" { // master password to be provided interactively
			for {
				masterPassword, err := internal.ReadSecret("Enter your master password: ")
				if err != nil {
					color.Yellow("An error occurred reading the password: " + err.Error())
					continue
				}
				safety, message := evaluatePassword(masterPassword)
				masterPasswordSHA3 = internal.HashAndDestroy(masterPassword)
				color.HiWhite(message)
				if safety == 0 {
					color.Yellow("Your password is not safe, please enter a more complicated password.")
					continue
				} else if safety == 1 {
					setStrongerPassword := internal.ReadInput("Your password is not very safe, would you like to enter a stronger password? (yes/no) [no]: ")
					if setStrongerPassword == "yes" {
						internal.ClearByteArray32(masterPasswordSHA3)
						continue
					}
				} else {
					color.HiGreen("Your password is very safe, good job!")
				}
				masterPasswordConfirm, err := internal.ReadSecret("Enter your master password again: ")
				if err != nil {
					color.Yellow("An error occurred reading the password confirmation: " + err.Error())
					continue
				}
				masterPasswordSHA3Confirm := internal.HashAndDestroy(masterPasswordConfirm)
				if !internal.ByteArrays32Equal(masterPasswordSHA3, masterPasswordSHA3Confirm) {
					color.Yellow("The passwords entered do not match, please try again.")
					internal.ClearByteArray32(masterPasswordSHA3)
					internal.ClearByteArray32(masterPasswordSHA3Confirm)
					continue
				}
				internal.ClearByteArray32(masterPasswordSHA3Confirm)
				break
			}
		}
		createP.masterPassword = ""

		if createP.birthdate == "" { // birthdate to be provided interactively
			for {
				birthdate, err := internal.ReadSecret("Enter your date of birth in the format dd/mm/yyyy: ")
				if err != nil {
					color.Yellow("An error occurred reading your birthdate: " + err.Error())
					continue
				}
				if !dateIsValid(birthdate) {
					color.Yellow("The birthdate you entered is not valid.")
					internal.ClearByteSlice(birthdate)
					continue
				}
				birthdateSHA3 = internal.HashAndDestroy(birthdate)
				birthdateConfirm, err := internal.ReadSecret("Enter your date of birth in the format dd/mm/yyyy again: ")
				if err != nil {
					color.Yellow("An error occurred reading your birthdate confirmation: " + err.Error())
					internal.ClearByteArray32(birthdateSHA3)
					continue
				}
				birthdateSHA3Confirm := internal.HashAndDestroy(birthdateConfirm)
				if !internal.ByteArrays32Equal(birthdateSHA3, birthdateSHA3Confirm) {
					color.Yellow("The birthdates entered do not match, please try again.")
					internal.ClearByteArray32(birthdateSHA3)
					internal.ClearByteArray32(birthdateSHA3Confirm)
					continue
				}
				color.HiGreen("Your birthdate is valid.")
				break
			}
		}
		createP.birthdate = ""

		if createP.pinCode == "" { // pin code to be provided interactively (optional)
			optionPin := internal.ReadInput("[OPTIONAL] To generate a password, would you like to setup a 4 digit pin code? (yes/no) [no]: ")
			if optionPin == "yes" {
				protection = "pin"
				for {
					pinCode, err := internal.ReadSecret("Please choose your PIN code in the format 9999: ")
					if err != nil {
						color.Yellow("An error occurred reading the PIN code: " + err.Error())
						continue
					}
					valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
					if !valid {
						color.Yellow("The PIN code you entered is not valid.")
						internal.ClearByteSlice(pinCode)
						continue
					}
					pinCodeSHA3 = internal.HashAndDestroy(pinCode)
					pinCodeConfirm, err := internal.ReadSecret("Please confirm your PIN code in the format 9999: ")
					if err != nil {
						color.Yellow("An error occurred reading the PIN code confirmation: " + err.Error())
						continue
					}
					pinCodeSHA3Confirm := internal.HashAndDestroy(pinCodeConfirm)
					if !internal.ByteArrays32Equal(pinCodeSHA3, pinCodeSHA3Confirm) {
						color.Yellow("The PIN codes entered do not match, please try again.")
						internal.ClearByteArray32(pinCodeSHA3)
						internal.ClearByteArray32(pinCodeSHA3Confirm)
						continue
					}
					break
				}
			}
		}
		createP.pinCode = ""

		user = createP.defaultUser
		createP.defaultUser = ""
		if user == "" {
			for {
				user = internal.ReadInput("Enter your default user (i.e. email@domain.com): ")
				if user == "" {
					color.Yellow("Please enter a non-empty user")
					continue
				}
				break
			}
		}

		color.HiWhite("Computing master digest...")
		// Launch progress bar
		stopchan := make(chan struct{})
		stoppedchan := make(chan struct{})
		go func() {
			defer close(stoppedchan)
			bar := pb.StartNew(int(constants.ArgonTimeCost))
			bar.SetRefreshRate(time.Millisecond * 150)
			bar.ShowCounters = false
			var i uint32
			for {
				select {
				default:
					if i == constants.ArgonTimeCost {
						bar.FinishPrint(color.HiGreenString("About to finish..."))
						return
					}
					bar.Increment()
					i++
					time.Sleep(time.Millisecond * time.Duration(argonTimePerRound))
				case <-stopchan:
					bar.FinishPrint(color.HiGreenString("Computation finished!"))
					return
				}
			}
		}()
		// Launch computation
		masterDigest := internal.CreateMasterDigest(masterPasswordSHA3, birthdateSHA3) // masterDigest is argonDigestSize bytes long

		// Clean up
		internal.ClearByteArray32(masterPasswordSHA3)
		internal.ClearByteArray32(birthdateSHA3)
		close(stopchan) // stop the progress bar
		<-stoppedchan   // wait for it to stop
		color.HiGreen("Master digest computed successfully")

		if protection == "pin" {
			internal.Checksumize(masterDigest)
			var decryptedMasterDigest *[]byte
			decryptedMasterDigest, err := internal.EncryptAES(masterDigest, pinCodeSHA3)
			if err != nil {
				color.HiRed("The following error occurred when encrypting the master digest: " + err.Error())
				return
			}
			masterDigest = decryptedMasterDigest
			internal.ClearByteArray32(pinCodeSHA3)
			color.HiGreen("\nMaster digest encrypted using PIN code successfully")
		}

		// TODO Yubikey with https://github.com/marshallbrekka/go-u2fhost
		err := internal.WriteMasterDigest(user, protection, masterDigest)
		internal.ClearByteSlice(masterDigest)
		if err != nil {
			color.HiRed("Error writing master digest to file: " + err.Error())
			return
		}
		color.HiGreen("Master digest saved successfully!")
	},
}

func dateIsValid(date *[]byte) bool {
	_, err := time.Parse("02/01/2006", string(*date))
	if err != nil {
		return false
	}
	return true
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
