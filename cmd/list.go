package cmd

import (
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

type listParams struct {
	startDate string
	endDate   string
	user      string
}

var listP listParams

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVar(&listP.startDate, "startdate", "", "Date in the format dd/mm/yyyy to list identifications from")
	listCmd.Flags().StringVar(&listP.endDate, "enddate", "", "Date in the format dd/mm/yyyy to list identifications up to")
	listCmd.Flags().StringVar(&listP.user, "user", "", "User to list identifications for")
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all identifications.",
	Long:  `Display all identifications you have generated.`,
	Run: func(cmd *cobra.Command, args []string) {
		var startUnix, endUnix int64 = 0, time.Now().Unix() // default values
		if listP.startDate != "" {
			t, err := time.Parse("02/01/2006", listP.startDate)
			if err != nil {
				color.HiRed("The start date provided is invalid (" + err.Error() + ")")
				return
			}
			startUnix = t.Unix()
		}
		if listP.endDate != "" {
			t, err := time.Parse("02/01/2006", listP.endDate)
			if err != nil {
				color.HiRed("The end date provided is invalid (" + err.Error() + ")")
				return
			}
			endUnix = t.Unix()
		}

		identifications, err := internal.GetAllIdentifications(startUnix, endUnix, listP.user)
		if err != nil {
			color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
			return
		}

		internal.DisplayIdentificationsCLI(identifications)
	},
}
