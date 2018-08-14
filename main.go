package main

import (
	"github.com/fatih/color"
	"github.com/techsek/derivatex/cmd"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

// TODO clipboard Linux, Unix (requires 'xclip' or 'xsel' command to be installed)

func main() {
	err := internal.InitiateDatabaseIfNeeded()
	if err != nil {
		color.HiRed("Error initiating database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
		return
	}
	cmd.Execute()
}
