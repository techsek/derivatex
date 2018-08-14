package cmd

import (
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

type deleteParams struct {
	startDate string
	endDate   string
	user      string
}

var deleteP deleteParams

func init() {
	rootCmd.AddCommand(deleteCmd)

	deleteCmd.Flags().StringVar(&deleteP.user, "user", "", "Specific user to delete the identification")
}

var deleteCmd = &cobra.Command{
	Use:   "delete <websitename>",
	Short: "Delete an identification matching the website name.",
	Long:  `Delete an identification matching the website name.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		website := args[0]
		identifications, err := internal.FindIdentificationsByWebsite(website)
		if err != nil {
			color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
			return
		}
		if len(identifications) == 0 {
			color.Yellow("No identification found for website '" + website + "'")
		} else if deleteP.user != "" {
			err = internal.DeleteIdentification(website, deleteP.user)
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
	},
}
