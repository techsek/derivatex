package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"

	"github.com/fatih/color"

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
	createCmd.Flags().StringVar(&createP.defaultUser, "user", "", "Your default user to be used when generating passwords without specifying a particular user")
}

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create the seed file",
	Long: `Create the seed.txt file from your master password and birthdate using Argon2ID. 
	Optionally (recommended) encrypt your seed.txt file with a randomly generated passphrase.
	This is forced to be run interactively for security reasons.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(color.HiWhiteString("Detecting performance of machine for Argon2ID..."))
		argonTimePerRound := internal.GetArgonTimePerRound()              // depends on the machine
		fmt.Println(color.HiGreenString("%dms/round", argonTimePerRound)) // TODO in goroutine
		var masterPasswordSHA3, birthdateSHA3 *[32]byte
		var protection = "none"
		for {
			masterPassword, err := internal.ReadSecret("Enter your master password: ")
			if err != nil {
				color.Yellow("An error occurred reading the password: " + err.Error())
				continue
			}
			safety, message := internal.EvaluatePassword(masterPassword)
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
		for {
			birthdate, err := internal.ReadSecret("Enter your date of birth in the format dd/mm/yyyy: ")
			if err != nil {
				color.Yellow("An error occurred reading your birthdate: " + err.Error())
				continue
			}
			if !internal.DateIsValid(birthdate) {
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

		if createP.defaultUser == "" {
			for {
				createP.defaultUser = internal.ReadInput("Enter your default user (i.e. email@domain.com): ")
				if createP.defaultUser == "" {
					color.Yellow("Please enter a user and try again.")
					continue
				}
				break
			}
		}

		color.HiWhite("Computing seed...")
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
		seed := internal.CreateSeed(masterPasswordSHA3, birthdateSHA3) // seed is argonDigestSize bytes long

		// Clean up
		internal.ClearByteArray32(masterPasswordSHA3)
		internal.ClearByteArray32(birthdateSHA3)
		close(stopchan) // stop the progress bar
		<-stoppedchan   // wait for it to stop
		color.HiGreen("Seed computed successfully")

		color.HiWhite("To generate a password, would you like to add one of the following securities:")
		fmt.Println("A: Randomly picked adjective and noun passphrase " + color.HiGreenString("(recommended)"))
		fmt.Println("B: Your own passphrase " + color.HiYellowString("(not recommended unless you know what you are doing)"))
		fmt.Println("C: None " + color.HiRedString("(not recommended unless you seed.txt is safe at all time)"))
		color.White(`For choices A and B, your seed and identifications database will be encrypted by AES
using a 256 bit key generated by Argon2ID from the passphrase. You will need that passphrase to do any further operation.`)
		for {
			protectionOption := internal.ReadInput("Please enter an additional security option [A]: ")
			if protectionOption == "A" || protectionOption == "" || protectionOption == "B" {
				protection = "passphrase"
				var passphrase string
				var err error
				if protectionOption == "A" || protectionOption == "" {
					for {
						passphrase, err = internal.MakePassphrase()
						if err != nil {
							color.Yellow("An error occurred when generating the passphrase: " + err.Error())
							continue
						}
						fmt.Println("Your generated passphrase is: " + color.HiGreenString(passphrase))
						anotherOne := internal.ReadInput("Would you prefer another passphrase? (yes/no) [yes]: ")
						if anotherOne == "" || anotherOne == "yes" {
							continue
						} else if anotherOne == "no" {
							break
						}
						color.Yellow("The answer '" + anotherOne + "' is not valid. Please try again.")
					}
				} else if protectionOption == "B" {
					passphrase = internal.ReadInput("Enter your passphrase: ")
				}
				passphraseBytes := []byte(passphrase)
				encryptedSeed, err := internal.EncryptSeed(seed, &passphraseBytes)
				if err != nil {
					color.HiRed("The following error occurred when encrypting the seed: " + err.Error())
					return
				}
				internal.ClearByteSlice(seed)
				seed = encryptedSeed
				color.HiGreen("Seed encrypted using passphrase successfully.")
				break
			} else if protectionOption == "C" {
				break
			}
			color.Yellow("Option '" + protectionOption + "' is not valid. Please try again.")
		}
		err := internal.WriteSeed(createP.defaultUser, protection, seed)
		internal.ClearByteSlice(seed)
		if err != nil {
			color.HiRed("Error writing seed to file: " + err.Error())
			return
		}
		color.HiGreen("Seed saved successfully!")
	},
}
