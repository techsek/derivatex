package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "derivatex",
	Short: "Derivatex is a smart pseudo-random password generator",
	Long: `Derivatex is a smart pseudo-random password generator. More
info can be found at https://github.com/techsek/derivatex`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("maybe print usage?")
	},
}

// Execute is the cli entrypoint
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
