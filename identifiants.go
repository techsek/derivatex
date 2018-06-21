package main

import (
	"database/sql"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Mostly about interacting with SQLite databse

var database *sql.DB

func initiateDatabaseIfNeeded() (err error) {
	database, err = sql.Open("sqlite3", "./"+databaseFilename)
	if err != nil {
		return err
	}
	var statement *sql.Stmt
	statement, err = database.Prepare(
		"CREATE TABLE IF NOT EXISTS identifications (website TEXT, user TEXT, password_length INTEGER, unix_time INTEGER, round INTEGER, version INTEGER, unallowed_characters TEXT, PRIMARY KEY(website, user))")
	if err != nil {
		return err
	}
	_, err = statement.Exec()
	if err != nil {
		return err
	}
	return nil
}

type identificationType struct {
	website             string
	user                string
	passwordLength      uint8 // max 255 otherwise it's ridiculous
	round               uint16
	unixTime            int64
	version             uint16
	unallowedCharacters string
}

func identificationTypeLegendStrings() []string {
	return []string{"Website", "User", "Password Length", "Round", "Date", "Program version", "Unallowed characters"}
}

func (identification *identificationType) toStrings() []string {
	return []string{
		identification.website,
		identification.user,
		strconv.FormatUint(uint64(identification.passwordLength), 10),
		strconv.FormatUint(uint64(identification.round), 10),
		time.Unix(identification.unixTime, 0).Format("02/01/2006"),
		strconv.FormatUint(uint64(identification.version), 10),
		identification.unallowedCharacters,
	}
}

func (identification *identificationType) equal(other *identificationType) bool {
	return identification.website == other.website &&
		identification.user == other.user &&
		identification.passwordLength == other.passwordLength &&
		identification.round == other.round &&
		identification.version == other.version &&
		identification.unallowedCharacters == other.unallowedCharacters
}

func findidentificationsByWebsite(website string) (identifications []identificationType, err error) {
	statement, err := database.Prepare("SELECT * FROM identifications WHERE website = ?")
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query(website)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identification identificationType
	for rows.Next() {
		err = rows.Scan(
			&identification.website,
			&identification.user,
			&identification.passwordLength,
			&identification.unixTime,
			&identification.round,
			&identification.version,
			&identification.unallowedCharacters,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}

func findidentification(website string, user string) (identification identificationType, err error) {
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
			&identification.website,
			&identification.user,
			&identification.passwordLength,
			&identification.unixTime,
			&identification.round,
			&identification.version,
			&identification.unallowedCharacters,
		)
		if err != nil {
			return identification, err
		}
	}
	return identification, nil
}

func insertidentification(identification identificationType) (err error) {
	statement, err := database.Prepare("INSERT INTO identifications (website, user, password_length, unix_time, round, version, unallowed_characters) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	_, err = statement.Exec(identification.website, identification.user, identification.passwordLength, identification.unixTime, identification.round, identification.version, identification.unallowedCharacters)
	return err
}

func searchidentifications(searchString string) (identifications []identificationType, err error) {
	statement, err := database.Prepare("SELECT * FROM identifications WHERE website LIKE ? OR user LIKE ?")
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query("%"+searchString+"%", "%"+searchString+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identification identificationType
	for rows.Next() {
		err = rows.Scan(
			&identification.website,
			&identification.user,
			&identification.passwordLength,
			&identification.unixTime,
			&identification.round,
			&identification.version,
			&identification.unallowedCharacters,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}

func dumpTable(tableName string) error {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return err
	}
	rows, err := database.Query("SELECT * FROM " + tableName)
	if err != nil {
		return err
	}
	defer rows.Close()
	var identification identificationType
	output := strings.Join(identificationTypeLegendStrings(), ",") + "\n"
	for rows.Next() {
		err = rows.Scan(
			&identification.website,
			&identification.user,
			&identification.passwordLength,
			&identification.unixTime,
			&identification.round,
			&identification.version,
			&identification.unallowedCharacters,
		)
		if err != nil {
			return err
		}
		output += strings.Join(identification.toStrings(), ",") + "\n"
	}
	err = ioutil.WriteFile(dir+"/"+tableName+".csv", []byte(output), 0644)
	return err
}

func deleteidentification(website string, user string) (err error) {
	statement, err := database.Prepare("DELETE FROM identifications WHERE website = ? AND user = ?")
	if err != nil {
		return err
	}
	_, err = statement.Exec(website, user)
	return err
}

func getAllidentifications() (identifications []identificationType, err error) {
	rows, err := database.Query("SELECT * FROM identifications")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identification identificationType
	for rows.Next() {
		err = rows.Scan(
			&identification.website,
			&identification.user,
			&identification.passwordLength,
			&identification.unixTime,
			&identification.round,
			&identification.version,
			&identification.unallowedCharacters,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}
