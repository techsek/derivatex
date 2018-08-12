package commands

import (
	"flag"
	"os"

	"github.com/derivatex/internal"
	"github.com/fatih/color"
)

var searchFlagSet = flag.NewFlagSet("search", flag.ExitOnError)

func Search(args []string) {
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
}

func searchCLI(query string, params *struct {
	searchWebsites bool
	searchUsers    bool
}) {
	identifications, err := internal.SearchIdentifications(query, params.searchWebsites, params.searchUsers)
	if err != nil {
		color.HiRed("The following error occurred when searching the identifications for '" + query + "': " + err.Error())
		return
	}
	if len(identifications) == 0 {
		color.HiWhite("No identification found for query string '" + os.Args[2] + "'")
		return
	}
	internal.DisplayIdentificationsCLI(identifications)
}
