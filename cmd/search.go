package cmd

import (
	"bytes"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/sahilm/fuzzy"
	"github.com/spf13/cobra"
	"github.com/techsek/derivatex/constants"
	"github.com/techsek/derivatex/internal"
)

type searchParams struct {
	websites bool
	users    bool
}

var searchP searchParams

func init() {
	rootCmd.AddCommand(searchCmd)
}

var searchCmd = &cobra.Command{
	Use:   "search <querystring>",
	Short: "Search identifications containing the query string",
	Long:  `Search identifications containing the query string.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		query := args[0]

		// Get all identifications
		var startUnix, endUnix int64 = 0, time.Now().Unix() // default values
		identifications, err := internal.GetAllIdentifications(startUnix, endUnix, "")
		if err != nil {
			color.HiRed("Error reading the database file '" + constants.DatabaseFilename + "' (" + err.Error() + ")")
			return
		}

		// Fuzzy search through all websites and users
		websiteMatches := fuzzy.Find(query, getWebsites(identifications))
		userMatches := fuzzy.Find(query, getUsers(identifications))

		if len(websiteMatches)+len(userMatches) == 0 {
			// No results found.
			color.HiRed("No results found.")
			return
		}

		websiteBoldedTerms := getTermToBoldedTermMap(websiteMatches)
		userBoldedTerms := getTermToBoldedTermMap(userMatches)

		// Generate a new array of identifications containing the
		// results of the fuzzy match with the found characters bolded.
		var foundIdentifications []internal.IdentificationType
		for _, identification := range identifications {
			found := false
			if val, ok := websiteBoldedTerms[identification.Website]; ok {
				identification.Website = val
				found = true
			}
			if val, ok := userBoldedTerms[identification.User]; ok {
				identification.User = val
				found = true
			}
			if found {
				foundIdentifications = append(foundIdentifications, identification)
			}
		}

		internal.DisplayIdentificationsCLI(foundIdentifications)
	},
}

// Generate a mapping between the matched string and a string containing
// the found characters in bold.
func getTermToBoldedTermMap(matches []fuzzy.Match) map[string]string {
	m := make(map[string]string)
	for _, match := range matches {
		var buffer bytes.Buffer
		for i := 0; i < len(match.Str); i++ {
			if contains(i, match.MatchedIndexes) {
				buffer.WriteString(fmt.Sprintf("\033[1m%s\033[0m", string(match.Str[i])))
			} else {
				buffer.WriteString(string(match.Str[i]))
			}
		}
		m[match.Str] = buffer.String()
	}
	return m
}

// Return an array of all users from the identifications
func getUsers(identifications []internal.IdentificationType) []string {
	var users []string
	for _, identification := range identifications {
		users = append(users, identification.User)
	}
	return users
}

// Return an array of all websites from the identifications
func getWebsites(identifications []internal.IdentificationType) []string {
	var websites []string
	for _, identification := range identifications {
		websites = append(websites, identification.Website)
	}
	return websites
}

func contains(needle int, haystack []int) bool {
	for _, i := range haystack {
		if needle == i {
			return true
		}
	}
	return false
}
