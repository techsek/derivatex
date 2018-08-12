package commands

import (
	"flag"
	"strings"

	"github.com/fatih/color"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

var deleteFlagSet = flag.NewFlagSet("delete", flag.ExitOnError)

func Delete(args []string) {
	var deleteParams struct {
		user string
	}
	deleteFlagSet.StringVar(&deleteParams.user, "user", "", "Specific user to delete the identification")
	deleteFlagSet.Parse(args[2:])
	if deleteFlagSet.Parsed() {
		deleteCLI(args[1], &deleteParams)
	}
}

func deleteCLI(website string, params *struct{ user string }) {
	identifications, err := internal.FindIdentificationsByWebsite(website)
	if err != nil {
		color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
		return
	}
	if len(identifications) == 0 {
		color.Yellow("No identification found for website '" + website + "'")
	} else if params.user != "" {
		err = internal.DeleteIdentification(website, params.user)
		if err != nil {
			color.HiRed("Error deleting the identification: " + err.Error())
			return
		}
		color.HiGreen("The following identification has been deleted from the database:\n" + strings.Join(identifications[0].ToStrings(), " | "))
	} else if len(identifications) == 1 {
		err = internal.DeleteIdentification(website, identifications[0].User)
		if err != nil {
			color.HiRed("Error deleting the identification: " + err.Error())
			return
		}
		color.HiGreen("The following identification has been deleted from the database:\n" + strings.Join(identifications[0].ToStrings(), " | "))
	} else {
		color.HiWhite(strings.Join(internal.IdentificationTypeLegendStrings(), " | "))
		for i := range identifications {
			color.White(strings.Join(identifications[i].ToStrings(), " | "))
		}
		var user string
		var identification internal.IdentificationType
		for {
			user = internal.ReadInput("Please specify which user you want to delete: ")
			identification, err = internal.FindIdentification(website, user)
			if err != nil {
				color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
				return
			}
			if identification.Website == "" { // not found
				color.Yellow("identification with website '" + website + "' and user '" + user + "' was not found. Please try again.")
				continue
			}
			break
		}
		err = internal.DeleteIdentification(website, user)
		if err != nil {
			color.HiRed("Error deleting the identification: " + err.Error())
			return
		}
		color.HiGreen("The following identification has been deleted from the database:\n" + strings.Join(identification.ToStrings(), " | "))
	}
}
