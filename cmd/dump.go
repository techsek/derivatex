package cmd

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

type dumpParams struct {
	tableName      string
	outputFilename string
}

var dumpP dumpParams

func init() {
	rootCmd.AddCommand(dumpCmd)

	dumpCmd.Flags().StringVar(&dumpP.tableName, "table", constants.DefaultTableToDump, "SQLite table name to dump to CSV file")
	dumpCmd.Flags().StringVar(&dumpP.outputFilename, "output", constants.DefaultTableToDump+".csv", "File name to store the CSV data")
}

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump database to a CSV file.",
	Long:  `Dump database to a CSV file.`,
	Run: func(cmd *cobra.Command, args []string) {
		if dumpP.outputFilename == "" {
			dumpP.outputFilename = dumpP.tableName + ".csv"
		}
		err := internal.DumpTable(dumpP.tableName, dumpP.outputFilename)
		if err != nil {
			color.HiRed("Database table " + dumpP.tableName + " could not be dumped to file because: " + err.Error())
			return
		}
		color.HiGreen("Database table " + dumpP.tableName + " was dumped to " + dumpP.outputFilename)
	},
}
