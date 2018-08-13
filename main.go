package main

import (
	"os"

	"github.com/techsek/derivatex/commands"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"

	"github.com/fatih/color"
)

// TODO clipboard Linux, Unix (requires 'xclip' or 'xsel' command to be installed)

func main() {
	err := internal.InitiateDatabaseIfNeeded()
	if err != nil {
		color.HiRed("Error initiating database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
	} else if len(os.Args) == 1 {
		commands.Help()
	} else {
		cli(os.Args[1:])
	}
}

func cli(args []string) {
	switch command := args[0]; command {
	case "create":
		commands.Create(args)
	case "generate": // TODO make better with default config options
		if len(args) < 2 {
			color.HiRed("Website name is missing after command generate")
			commands.Help()
			return
		}
		commands.Generate(args)
	case "list":
		commands.List(args)
	case "search":
		if len(args) < 2 {
			color.HiRed("Search query string is missing after command search")
			commands.Help()
			return
		}
		commands.Search(args)
	case "delete":
		if len(args) < 2 {
			color.HiRed("Website string to delete is missing after command delete")
			commands.Help()
			return
		}
		commands.Delete(args)
	case "dump":
		commands.Dump(args)
	case "help":
		commands.Help()
	default:
		color.HiRed("Command '" + command + "' not recognized.")
		commands.Help()
	}
}
