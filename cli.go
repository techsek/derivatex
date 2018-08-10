package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/mdp/qrterminal"
	ps "github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/ssh/terminal"
	pb "gopkg.in/cheggaaa/pb.v1"
)

func displayUsage() {
	fmt.Println(color.HiWhiteString("derivatex usage:") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("create") + " " + color.HiCyanString("[-password=] [-birthdate=] [-user=] [-pin=]") + "\n" + color.HiWhiteString("Create the master password digest needed to generate passwords interactively (safer) and/or with command line flags (riskier due to commands history saved).") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("generate") + " " + color.HiGreenString("websitename") + " " + color.HiCyanString("[-length="+strconv.FormatInt(defaultPasswordLength, 10)+"] [-birthdate=] [-user=] [-pin=] [-qrcode=true] [-clipboard=true] [-passwordonly] [-save=true] [-version="+strconv.FormatInt(version, 10)+"]") + "\n" + color.HiWhiteString("Generate a password for a particular website name. Optional flags are available for custom password generation.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("list") + " " + color.HiCyanString("[-startdate=] [-enddate=] [-user=]") + "\n" + color.HiWhiteString("List all identifications. Optionally set a start date and end date (dd/mm/yyyy) and a specific user.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("search") + " " + color.HiGreenString("querystring") + " " + color.HiCyanString("[-websites=true] [-users=true]") + "\n" + color.HiWhiteString("Search identifications containing the query string. Optionally restrict the fields to search in.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("delete") + " " + color.HiGreenString("websitename") + " " + color.HiCyanString("[-user=]") + "\n" + color.HiWhiteString("Delete an identifications matching the website name. Optionally set the user in case there are multiple users registered for this website.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("dump") + " " + color.HiCyanString("[-tablename="+defaultTableToDump+"] [-outputfilename="+defaultTableToDump+".csv]") + "\n" + color.HiWhiteString("Dump a database table to a CSV file. Optionally set a different table to dump and/or a different output filename.") +
		"\n" + color.WhiteString("derivatex") + " " + color.HiBlueString("help") + "\n" + color.HiWhiteString("Displays this usage message."))
}

var createFlagSet, generateFlagSet, dumpFlagSet, searchFlagSet, deleteFlagSet, listFlagSet *flag.FlagSet

func init() {
	createFlagSet = flag.NewFlagSet("create", flag.ExitOnError)
	generateFlagSet = flag.NewFlagSet("generate", flag.ExitOnError)
	listFlagSet = flag.NewFlagSet("list", flag.ExitOnError)
	searchFlagSet = flag.NewFlagSet("search", flag.ExitOnError)
	deleteFlagSet = flag.NewFlagSet("delete", flag.ExitOnError)
	dumpFlagSet = flag.NewFlagSet("dump", flag.ExitOnError)
}

func cli(args []string) {
	switch command := args[0]; command {
	case "create":
		var createParams struct {
			masterPassword, birthdate, defaultUser, pinCode string
		}
		createFlagSet.StringVar(&createParams.masterPassword, "password", "", "Master password to be used to generate the digest file (you should not use this flag for better security)")
		createFlagSet.StringVar(&createParams.birthdate, "birthdate", "", "Your birthdate in the format dd/mm/yyyy (you should not use this flag for better security)")
		createFlagSet.StringVar(&createParams.defaultUser, "user", "", "Your default user to be used when generating passwords without specifying a particular user")
		createFlagSet.StringVar(&createParams.pinCode, "pin", "", "An optional 4 digit code to encrypt your digest file (you should not use this flag for better security)")
		createFlagSet.Parse(args[1:])
		if createFlagSet.Parsed() {
			createCLI(&createParams)
		}
	case "generate": // TODO make better with default config options
		if len(args) < 2 {
			color.HiRed("Website name is missing after command generate")
			displayUsage()
			return
		}
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
		generateFlagSet.IntVar(&generateParams.passwordLength, "length", defaultPasswordLength, "Length of the derived password")
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
		generateFlagSet.IntVar(&generateParams.programVersion, "version", version, "Version of the core password generation code to be used")
		generateFlagSet.Parse(args[2:])
		if generateFlagSet.Parsed() {
			generateCLI(args[1], &generateParams)
		}
	case "list":
		var listParams struct {
			startDate string
			endDate   string
			user      string
		}
		listFlagSet.StringVar(&listParams.startDate, "startdate", "", "Date in the format dd/mm/yyyy to list identifications from")
		listFlagSet.StringVar(&listParams.endDate, "enddate", "", "Date in the format dd/mm/yyyy to list identifications up to")
		listFlagSet.StringVar(&listParams.user, "user", "", "User to list identifications for")
		listFlagSet.Parse(args[1:])
		if listFlagSet.Parsed() {
			listCLI(&listParams)
		}
	case "search":
		if len(args) < 2 {
			color.HiRed("Search query string is missing after command search")
			displayUsage()
			return
		}
		var searchParams struct {
			searchWebsites bool
			searchUsers    bool
		}
		searchFlagSet.BoolVar(&searchParams.searchWebsites, "websites", true, "Search query into website names")
		searchFlagSet.BoolVar(&searchParams.searchUsers, "users", true, "Search query into users")
		searchFlagSet.Parse(args[2:])
		if searchFlagSet.Parsed() {
			searchCLI(args[1], &searchParams)
		}
	case "delete":
		if len(args) < 2 {
			color.HiRed("Website string to delete is missing after command delete")
			displayUsage()
			return
		}
		var deleteParams struct {
			user string
		}
		deleteFlagSet.StringVar(&deleteParams.user, "user", "", "Specific user to delete the identification")
		deleteFlagSet.Parse(args[2:])
		if deleteFlagSet.Parsed() {
			deleteCLI(args[1], &deleteParams)
		}
	case "dump":
		var dumpParams struct {
			tableName      string
			outputfilename string
		}
		dumpFlagSet.StringVar(&dumpParams.tableName, "table", defaultTableToDump, "SQLite table name to dump to CSV file")
		dumpFlagSet.StringVar(&dumpParams.outputfilename, "output", defaultTableToDump+".csv", "File name to store the CSV data")
		dumpFlagSet.Parse(args[1:])
		if dumpFlagSet.Parsed() {
			dumpCLI(&dumpParams)
			// TODO fix paths
		}
	case "help":
		displayUsage()
	default:
		color.HiRed("Command '" + command + "' not recognized.")
		displayUsage()
	}
}

func createCLI(params *struct {
	masterPassword string
	birthdate      string
	defaultUser    string
	pinCode        string
}) {
	fmt.Printf(color.HiWhiteString("Detecting performance of machine for Argon2ID..."))
	argonTimePerRound := getArgonTimePerRound()                       // depends on the machine
	fmt.Println(color.HiGreenString("%dms/round", argonTimePerRound)) // TODO in goroutine

	var masterPasswordSHA3, birthdateSHA3, pinCodeSHA3 *[32]byte
	var user string
	var protection = "none"
	if params.masterPassword != "" { // master password provided in argument
		color.Yellow("Your password was provided as a command line flag, but it is safer to provide it within the interactive command line interface of derivatex.")
		masterPassword := []byte(params.masterPassword)
		safety, message := evaluatePassword(&masterPassword)
		masterPasswordSHA3 = hashAndDestroy(&masterPassword)
		color.HiWhite(message)
		if safety == 0 {
			clearByteArray32(masterPasswordSHA3)
			color.HiRed("Your password is not safe, please enter a more complicated password.")
			return
		} else if safety == 1 {
			color.Yellow("Your password is not very safe, you might want to abort (CTRL + C) and use a stronger password")
		}
	}
	if params.birthdate != "" { // birthdate provided in argument
		color.Yellow("Your birthdate was provided as a command line flag, but it is safer to provide it within the interactive command line interface of derivatex.")
		birthdateBytes := []byte(params.birthdate)
		var birthdate = &birthdateBytes
		if !dateIsValid(birthdate) {
			color.HiRed("The birthdate you entered is not valid.")
			clearByteSlice(birthdate)
			return
		}
		birthdateSHA3 = hashAndDestroy(birthdate)
	}
	if params.pinCode != "" { // pin code provided in argument
		color.Yellow("Your encryption 4 digit code was provided as a command line flag, but it is safer to provide it within the interactive command line interface of Derivatex.")
		pinCodeBytes := []byte(params.pinCode)
		pinCode := &pinCodeBytes
		protection = "pin"
		valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
		if !valid {
			clearByteSlice(pinCode)
			color.HiRed("Your 4 digit code is not valid.")
			return
		}
		pinCodeSHA3 = hashAndDestroy(pinCode)
	}

	if params.masterPassword == "" { // master password to be provided interactively
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
	}
	params.masterPassword = ""

	if params.birthdate == "" { // birthdate to be provided interactively
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
	}
	params.birthdate = ""

	if params.pinCode == "" { // pin code to be provided interactively (optional)
		optionPin := readInput("[OPTIONAL] To generate a password, would you like to setup a 4 digit pin code? (yes/no) [no]: ")
		if optionPin == "yes" {
			protection = "pin"
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
				break
			}
		}
	}
	params.pinCode = ""

	user = params.defaultUser
	params.defaultUser = ""
	if user == "" {
		for {
			user = readInput("Enter your default user (i.e. email@domain.com): ")
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
		bar := pb.StartNew(int(argonTimeCost))
		bar.SetRefreshRate(time.Millisecond * 150)
		bar.ShowCounters = false
		var i uint32
		for {
			select {
			default:
				if i == argonTimeCost {
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
	masterDigest := createMasterDigest(masterPasswordSHA3, birthdateSHA3) // masterDigest is argonDigestSize bytes long

	// Clean up
	clearByteArray32(masterPasswordSHA3)
	clearByteArray32(birthdateSHA3)
	close(stopchan) // stop the progress bar
	<-stoppedchan   // wait for it to stop
	color.HiGreen("Master digest computed successfully")

	if protection == "pin" {
		checksumize(masterDigest)
		var decryptedMasterDigest *[]byte
		decryptedMasterDigest, err := encryptAES(masterDigest, pinCodeSHA3)
		if err != nil {
			color.HiRed("The following error occurred when encrypting the master digest: " + err.Error())
			return
		}
		masterDigest = decryptedMasterDigest
		clearByteArray32(pinCodeSHA3)
		color.HiGreen("\nMaster digest encrypted using PIN code successfully")
	}

	// TODO Yubikey with https://github.com/marshallbrekka/go-u2fhost
	err := writeMasterDigest(user, protection, masterDigest)
	clearByteSlice(masterDigest)
	if err != nil {
		color.HiRed("Error writing master digest to file: " + err.Error())
		return
	}
	color.HiGreen("Master digest saved successfully!")
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
	unallowedCharacters := buildUnallowedCharacters(params.noSymbol, params.noDigit, params.noUppercase, params.noLowercase, params.excludedCharacters)
	if !unallowedCharacters.isAnythingAllowed() {
		color.HiRed("The password can't be generated with all possible characters excluded")
		return
	}
	defaultUser, protection, masterDigest, err := readMasterDigest()
	if err != nil {
		color.Yellow("An error occurred reading the master digest file: " + err.Error())
		return
	}
	if protection == "pin" && params.pinCode != "" { // pinCode provided as argument
		pinCodeBytes := []byte(params.pinCode)
		pinCode := &pinCodeBytes
		valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
		if !valid {
			clearByteSlice(pinCode)
			color.HiRed("The PIN code you entered is not in the valid format.")
			return
		}
		var pinCodeSHA3 = hashAndDestroy(pinCode)
		decryptedMasterDigest, err := decryptAES(masterDigest, pinCodeSHA3)
		clearByteArray32(pinCodeSHA3)
		if err != nil {
			clearByteSlice(decryptedMasterDigest)
			color.HiRed("Decryption error: " + err.Error())
			return
		}
		err = dechecksumize(decryptedMasterDigest)
		if err != nil {
			clearByteSlice(decryptedMasterDigest)
			color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
			return
		}
		clearByteSlice(masterDigest)
		masterDigest = decryptedMasterDigest
	}

	user := defaultUser
	if params.user != "" { // user flag provided
		user = params.user
	}

	newIdentification := identificationType{
		website:             website,
		user:                user,
		passwordLength:      uint8(params.passwordLength),
		round:               uint16(params.round),
		unallowedCharacters: unallowedCharacters.serialize(),
		creationTime:        time.Now().Unix(), // set to previous database record if a record is found
		programVersion:      uint16(params.programVersion),
		note:                params.note,
	}
	identifications, err := findIdentificationsByWebsite(website)
	if err != nil {
		color.HiRed("Error reading the database file '" + databaseFilename + "' (" + err.Error() + ")")
		return
	}
	var replaceIdentification bool
	if len(identifications) > 0 {
		var identificationExists bool
		for i := range identifications {
			if newIdentification.user == identifications[i].user { // identification already exists in database
				identificationExists = true
				if identifications[i].generationParamsEqualTo(&newIdentification) {
					newIdentification.creationTime = identifications[i].creationTime
				} else {
					color.HiWhite("A password for the following identification has already been generated previously:")
					color.White(strings.Join(identificationTypeLegendStrings(), " | "))
					color.White(strings.Join(identifications[i].toStrings(), " | "))
					color.HiWhite("You are trying to create a password with the following identification:")
					color.White(strings.Join(identificationTypeLegendStrings(), " | "))
					color.White(strings.Join(newIdentification.toStrings(), " | "))
					for {
						replaceOrOld := readInput("Replace the old identification or generate using the old identification? (replace/old) [old]: ")
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
			if len(identifications) == 1 && newIdentification.isDefault(params.user == "") { // lazy generating
				color.Yellow("This password is assumed to be generated for user '" + identifications[0].user + "' using the corresponding stored settings.")
				newIdentification = identifications[0]
			} else {
				color.HiWhite("Password(s) for the following identification(s) have already been generated previously:")
				displayIdentificationsCLI(identifications)
				for {
					continueGenerate := readInput("Generate a password for '" + website + "' and new user '" + user + "'? (yes/no) [no]: ")
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
			pinCode, err := readSecret("Enter your PIN code to decrypt the master digest: ")
			if err != nil {
				color.Yellow("An error occurred reading the PIN code: " + err.Error())
				continue
			}
			valid, _ := regexp.Match("^[0-9]{4}$", *pinCode)
			if !valid {
				clearByteSlice(pinCode)
				color.Yellow("The PIN code you entered is not in the valid format.")
				continue
			}
			pinCodeSHA3 = hashAndDestroy(pinCode)
			decryptedMasterDigest, err = decryptAES(masterDigest, pinCodeSHA3)
			clearByteArray32(pinCodeSHA3)
			if err != nil {
				clearByteSlice(decryptedMasterDigest)
				color.HiRed("Decryption error: " + err.Error())
				continue
			}
			err = dechecksumize(decryptedMasterDigest)
			if err != nil {
				clearByteSlice(decryptedMasterDigest)
				color.HiRed("Master digest or PIN Code is invalid - " + err.Error())
				continue
			}
			clearByteSlice(masterDigest)
			masterDigest = decryptedMasterDigest
			break
		}
	}
	params.pinCode = ""

	var password string
	if newIdentification.programVersion == 1 {
		password = determinePassword(masterDigest, []byte(website), []byte{}, newIdentification.passwordLength, newIdentification.round, unallowedCharacters)
	} else {
		password = determinePassword(masterDigest, []byte(website), []byte(user), newIdentification.passwordLength, newIdentification.round, unallowedCharacters)
	}

	if params.save {
		// TODO transaction
		if replaceIdentification {
			err := deleteIdentification(newIdentification.website, newIdentification.user)
			if err != nil {
				color.HiRed("Error deleting the identification: " + err.Error())
				return
			}
		}
		insertIdentification(newIdentification)
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
	fmt.Println(color.HiGreenString("User: ") + color.HiWhiteString(newIdentification.user))
	fmt.Println(color.HiGreenString("Password: ") + color.HiWhiteString(password))
	if params.clipboard {
		clipboard.WriteAll(password)
		color.HiGreen("Password copied to clipboard")
	}
}

func listCLI(params *struct {
	startDate string
	endDate   string
	user      string
}) {
	var startUnix, endUnix int64 = 0, time.Now().Unix() // default values
	if params.startDate != "" {
		t, err := time.Parse("02/01/2006", params.startDate)
		if err != nil {
			color.HiRed("The start date provided is invalid (" + err.Error() + ")")
			return
		}
		startUnix = t.Unix()
	}
	if params.endDate != "" {
		t, err := time.Parse("02/01/2006", params.endDate)
		if err != nil {
			color.HiRed("The end date provided is invalid (" + err.Error() + ")")
			return
		}
		endUnix = t.Unix()
	}
	identifications, err := getAllIdentifications(startUnix, endUnix, params.user)
	if err != nil {
		color.HiRed("Error reading the database file '" + databaseFilename + "' (" + err.Error() + ")")
		return
	}
	displayIdentificationsCLI(identifications)
}

func searchCLI(query string, params *struct {
	searchWebsites bool
	searchUsers    bool
}) {
	identifications, err := searchIdentifications(query, params.searchWebsites, params.searchUsers)
	if err != nil {
		color.HiRed("The following error occurred when searching the identifications for '" + query + "': " + err.Error())
		return
	}
	if len(identifications) == 0 {
		color.HiWhite("No identification found for query string '" + os.Args[2] + "'")
		return
	}
	displayIdentificationsCLI(identifications)
}

func deleteCLI(website string, params *struct{ user string }) {
	identifications, err := findIdentificationsByWebsite(website)
	if err != nil {
		color.HiRed("Error reading the database file '" + databaseFilename + "' (" + err.Error() + ")")
		return
	}
	if len(identifications) == 0 {
		color.Yellow("No identification found for website '" + website + "'")
	} else if params.user != "" {
		err = deleteIdentification(website, params.user)
		if err != nil {
			color.HiRed("Error deleting the identification: " + err.Error())
			return
		}
		color.HiGreen("The following identification has been deleted from the database:\n" + strings.Join(identifications[0].toStrings(), " | "))
	} else if len(identifications) == 1 {
		err = deleteIdentification(website, identifications[0].user)
		if err != nil {
			color.HiRed("Error deleting the identification: " + err.Error())
			return
		}
		color.HiGreen("The following identification has been deleted from the database:\n" + strings.Join(identifications[0].toStrings(), " | "))
	} else {
		color.HiWhite(strings.Join(identificationTypeLegendStrings(), " | "))
		for i := range identifications {
			color.White(strings.Join(identifications[i].toStrings(), " | "))
		}
		var user string
		var identification identificationType
		for {
			user = readInput("Please specify which user you want to delete: ")
			identification, err = findIdentification(website, user)
			if err != nil {
				color.HiRed("Error reading the database file '" + databaseFilename + "' (" + err.Error() + ")")
				return
			}
			if identification.website == "" { // not found
				color.Yellow("identification with website '" + website + "' and user '" + user + "' was not found. Please try again.")
				continue
			}
			break
		}
		err = deleteIdentification(website, user)
		if err != nil {
			color.HiRed("Error deleting the identification: " + err.Error())
			return
		}
		color.HiGreen("The following identification has been deleted from the database:\n" + strings.Join(identification.toStrings(), " | "))
	}
}

func dumpCLI(params *struct {
	tableName      string
	outputfilename string
}) {
	if params.outputfilename == "" {
		params.outputfilename = params.tableName + ".csv"
	}
	err := dumpTable(params.tableName, params.outputfilename)
	if err != nil {
		color.HiRed("Database table " + params.tableName + " could not be dumped to file because: " + err.Error())
		return
	}
	color.HiGreen("Database table " + params.tableName + " was dumped to " + params.outputfilename)
}

func readInput(prompt string) (input string) {
	fmt.Print(color.HiMagentaString(prompt))
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		input = scanner.Text()
	}
	return input
}

func readSecret(prompt string) (secretPtr *[]byte, err error) {
	fmt.Print(color.HiMagentaString(prompt))
	secretPtr = new([]byte)
	*secretPtr, err = terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\n")
	if err != nil {
		return nil, err
	}
	return secretPtr, nil
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
