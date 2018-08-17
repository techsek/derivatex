package internal

import (
	"database/sql"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cast"
	"github.com/techsek/derivatex/constants"
)

// Mostly about interacting with SQLite databse

var database *sql.DB

func InitiateDatabaseIfNeeded() (err error) {
	database, err = sql.Open("sqlite3", "./"+constants.DatabaseFilename)
	if err != nil {
		return err
	}
	var statement *sql.Stmt
	statement, err = database.Prepare(
		"CREATE TABLE IF NOT EXISTS identifications (website TEXT, user TEXT, password_length INTEGER, round INTEGER, unallowed_characters TEXT, creation_time INTEGER, program_version INTEGER, note TEXT, PRIMARY KEY(website, user))")
	if err != nil {
		return err
	}
	_, err = statement.Exec()
	if err != nil {
		return err
	}
	return nil
}

type IdentificationType struct {
	Website                   string
	User                      string
	PasswordLength            uint8 // max 255 otherwise it's ridiculous
	Round                     uint16
	UnallowedCharacters       string
	CreationTime              int64
	PasswordDerivationVersion uint16
	Note                      string
}

func IdentificationTypeLegendStrings() []string {
	return []string{"Website", "User", "Password Length", "Round", "Unallowed characters", "Creation date", "Program version", "Note"}
}

func (identification *IdentificationType) ToStrings() []string {
	return []string{
		identification.Website,
		identification.User,
		strconv.FormatUint(uint64(identification.PasswordLength), 10),
		strconv.FormatUint(uint64(identification.Round), 10),
		identification.UnallowedCharacters,
		time.Unix(identification.CreationTime, 0).Format("02/01/2006"),
		strconv.FormatUint(uint64(identification.PasswordDerivationVersion), 10),
		identification.Note,
	}
}

func (identification *IdentificationType) GenerationParamsEqualTo(other *IdentificationType) bool {
	return identification.Website == other.Website &&
		identification.User == other.User &&
		identification.PasswordLength == other.PasswordLength &&
		identification.Round == other.Round &&
		identification.UnallowedCharacters == other.UnallowedCharacters &&
		identification.PasswordDerivationVersion == other.PasswordDerivationVersion
}

func (identification *IdentificationType) HasDefaultParams(userIsDefault bool) bool {
	return userIsDefault &&
		identification.PasswordLength == constants.DefaultPasswordLength &&
		identification.Round == 1 &&
		identification.UnallowedCharacters == "" &&
		identification.PasswordDerivationVersion == constants.PasswordDerivationVersion &&
		identification.Note == ""
}

func FindIdentificationsByWebsite(website string) (identifications []IdentificationType, err error) {
	statement, err := database.Prepare("SELECT * FROM identifications WHERE website = ?")
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query(website)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identification IdentificationType
	for rows.Next() {
		err = rows.Scan(
			&identification.Website,
			&identification.User,
			&identification.PasswordLength,
			&identification.Round,
			&identification.UnallowedCharacters,
			&identification.CreationTime,
			&identification.PasswordDerivationVersion,
			&identification.Note,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}

func FindIdentification(website string, user string) (identification IdentificationType, err error) {
	statement, err := database.Prepare("SELECT * FROM identifications WHERE website = ? AND user = ?")
	if err != nil {
		return identification, err
	}
	rows, err := statement.Query(website, user)
	if err != nil {
		return identification, err
	}
	defer rows.Close()
	if rows.Next() {
		err = rows.Scan(
			&identification.Website,
			&identification.User,
			&identification.PasswordLength,
			&identification.Round,
			&identification.UnallowedCharacters,
			&identification.CreationTime,
			&identification.PasswordDerivationVersion,
			&identification.Note,
		)
		if err != nil {
			return identification, err
		}
	}
	return identification, nil
}

func InsertIdentification(identification IdentificationType) (err error) {
	statement, err := database.Prepare("INSERT INTO identifications (website, user, password_length, round, unallowed_characters, creation_time, program_version, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	_, err = statement.Exec(identification.Website, identification.User, identification.PasswordLength, identification.Round, identification.UnallowedCharacters, identification.CreationTime, identification.PasswordDerivationVersion, identification.Note)
	return err
}

func SearchIdentifications(query string, searchWebsites, searchUsers bool) (identifications []IdentificationType, err error) {
	var websiteQuery, userQuery string
	if searchWebsites {
		websiteQuery = "%" + query + "%"
	}
	if searchUsers {
		userQuery = "%" + query + "%"
	}
	statement, err := database.Prepare("SELECT * FROM identifications WHERE website LIKE ? OR user LIKE ?")
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query(websiteQuery, userQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identification IdentificationType
	for rows.Next() {
		err = rows.Scan(
			&identification.Website,
			&identification.User,
			&identification.PasswordLength,
			&identification.Round,
			&identification.UnallowedCharacters,
			&identification.CreationTime,
			&identification.PasswordDerivationVersion,
			&identification.Note,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}

func DumpTable(tableName string, outputfilename string) error {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	rows, err := database.Query("SELECT * FROM " + tableName)
	if err != nil {
		return err
	}
	defer rows.Close()
	var identification IdentificationType
	output := strings.Join(IdentificationTypeLegendStrings(), ",") + "\n"
	for rows.Next() {
		err = rows.Scan(
			&identification.Website,
			&identification.User,
			&identification.PasswordLength,
			&identification.Round,
			&identification.UnallowedCharacters,
			&identification.CreationTime,
			&identification.PasswordDerivationVersion,
			&identification.Note,
		)
		if err != nil {
			return err
		}
		output += strings.Join(identification.ToStrings(), ",") + "\n"
	}
	err = ioutil.WriteFile(dir+"/"+outputfilename, []byte(output), 0644)
	return err
}

func DeleteIdentification(website string, user string) (err error) {
	statement, err := database.Prepare("DELETE FROM identifications WHERE website = ? AND user = ?")
	if err != nil {
		return err
	}
	_, err = statement.Exec(website, user)
	return err
}

func GetAllIdentifications(startTime, endTime int64, user string) (identifications []IdentificationType, err error) {
	var rows *sql.Rows
	if user == "" {
		statement, err := database.Prepare("SELECT * FROM identifications WHERE creation_time > ? AND creation_time < ?")
		if err != nil {
			return nil, err
		}
		rows, err = statement.Query(startTime, endTime)
		if err != nil {
			return nil, err
		}
	} else {
		statement, err := database.Prepare("SELECT * FROM identifications WHERE creation_time > ? AND creation_time < ? AND user = ?")
		if err != nil {
			return nil, err
		}
		rows, err = statement.Query(startTime, endTime, user)
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()
	var identification IdentificationType
	for rows.Next() {
		err = rows.Scan(
			&identification.Website,
			&identification.User,
			&identification.PasswordLength,
			&identification.Round,
			&identification.UnallowedCharacters,
			&identification.CreationTime,
			&identification.PasswordDerivationVersion,
			&identification.Note,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}

func DisplayIdentificationCLI(identification IdentificationType) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetColWidth(0)
	table.SetHeader(IdentificationTypeLegendStrings())
	value := reflect.ValueOf(identification)
	var row []string
	for i := 0; i < value.NumField(); i++ {
		row = append(row, cast.ToString(value.Field(i).Interface()))
	}
	table.Append(row)
	table.Render()
}

func DisplayIdentificationsCLI(identifications []IdentificationType) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetColWidth(0)
	table.SetHeader(IdentificationTypeLegendStrings())
	for _, identification := range identifications {
		value := reflect.ValueOf(identification)
		var row []string
		for i := 0; i < value.NumField(); i++ {
			row = append(row, cast.ToString(value.Field(i).Interface()))
		}
		table.Append(row)
	}
	table.Render()
}

func ExtractUsers(identifications []IdentificationType) (users []string) {
	for _, identification := range identifications {
		users = append(users, identification.User)
	}
	return users
}

func DisplaySingleColumnCLI(title string, users []string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetColWidth(0)
	table.SetHeader([]string{title})
	for _, user := range users {
		table.Append([]string{user})
	}
	table.Render()
}
