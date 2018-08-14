package cmd

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/internal"
)

type searchParams struct {
	websites bool
	users    bool
}

var searchP searchParams

func init() {
	rootCmd.AddCommand(searchCmd)

	searchCmd.Flags().BoolVar(&searchP.websites, "websites", true, "Search query into website names")
	searchCmd.Flags().BoolVar(&searchP.users, "users", true, "Search query into users")
}

var searchCmd = &cobra.Command{
	Use:   "search <querystring>",
	Short: "Search identifications containing the query string.",
	Long:  `Search identifications containing the query string.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]
		identifications, err := internal.SearchIdentifications(query, searchP.websites, searchP.users)
		if err != nil {
			color.HiRed("The following error occurred when searching the identifications for '" + query + "': " + err.Error())
			return
		}
		if len(identifications) == 0 {
			color.HiWhite("No identification found for query string '" + query + "'")
			return
		}
		internal.DisplayIdentificationsCLI(identifications)
	},
}
