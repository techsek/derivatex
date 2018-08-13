package commands

import (
	"flag"

	"github.com/fatih/color"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

var dumpFlagSet = flag.NewFlagSet("dump", flag.ExitOnError)

func Dump(args []string) {
	var dumpParams struct {
		tableName      string
		outputfilename string
	}
	dumpFlagSet.StringVar(&dumpParams.tableName, "table", constants.DefaultTableToDump, "SQLite table name to dump to CSV file")
	dumpFlagSet.StringVar(&dumpParams.outputfilename, "output", constants.DefaultTableToDump+".csv", "File name to store the CSV data")
	dumpFlagSet.Parse(args[1:])
	if dumpFlagSet.Parsed() {
		dumpCLI(&dumpParams)
		// TODO fix paths
	}
}

func dumpCLI(params *struct {
	tableName      string
	outputfilename string
}) {
	if params.outputfilename == "" {
		params.outputfilename = params.tableName + ".csv"
	}
	err := internal.DumpTable(params.tableName, params.outputfilename)
	if err != nil {
		color.HiRed("Database table " + params.tableName + " could not be dumped to file because: " + err.Error())
		return
	}
	color.HiGreen("Database table " + params.tableName + " was dumped to " + params.outputfilename)
}
