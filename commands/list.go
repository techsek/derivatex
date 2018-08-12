package commands

import (
	"flag"
	"time"

	"github.com/derivatex/constants"
	"github.com/derivatex/internal"
	"github.com/fatih/color"
)

var listFlagSet = flag.NewFlagSet("list", flag.ExitOnError)

func List(args []string) {
	var listParams struct {
		startDate string
		endDate   string
		user      string
	}
	listFlagSet.StringVar(&listParams.startDate, "startdate", "", "Date in the format dd/mm/yyyy to list identifications from")
	listFlagSet.StringVar(&listParams.endDate, "enddate", "", "Date in the format dd/mm/yyyy to list identifications up to")
	listFlagSet.StringVar(&listParams.user, "user", "", "User to list identifications for")
	listFlagSet.Parse(args)
	if listFlagSet.Parsed() {
		listCLI(&listParams)
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
	identifications, err := internal.GetAllIdentifications(startUnix, endUnix, params.user)
	if err != nil {
		color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
		return
	}
	internal.DisplayIdentificationsCLI(identifications)
}
