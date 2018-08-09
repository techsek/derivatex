package main

import (
	"os"

	"github.com/fatih/color"
)

// TODO clipboard Linux, Unix (requires 'xclip' or 'xsel' command to be installed)

func main() {
	err := initiateDatabaseIfNeeded()
	if err != nil {
		color.HiRed("Error initiating database file '" + databaseFilename + "' (" + err.Error() + ")")
	} else if len(os.Args) == 1 {
		displayUsage()
	} else {
		cli(os.Args[1:])
	}
}
