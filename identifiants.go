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

type identificationType struct {
	website             string
	user                string
	passwordLength      uint8 // max 255 otherwise it's ridiculous
	round               uint16
	unallowedCharacters string
	creationTime        int64
	programVersion      uint16
	note                string
}

func identificationTypeLegendStrings() []string {
	return []string{"Website", "User", "Password Length", "Round", "Unallowed characters", "Creation date", "Program version", "Note"}
}

func (identification *identificationType) toStrings() []string {
	return []string{
		identification.website,
		identification.user,
		strconv.FormatUint(uint64(identification.passwordLength), 10),
		strconv.FormatUint(uint64(identification.round), 10),
		identification.unallowedCharacters,
		time.Unix(identification.creationTime, 0).Format("02/01/2006"),
		strconv.FormatUint(uint64(identification.programVersion), 10),
		identification.note,
	}
}

func (identification *identificationType) generationParamsEqualTo(other *identificationType) bool {
	return identification.website == other.website &&
		identification.user == other.user &&
		identification.passwordLength == other.passwordLength &&
		identification.round == other.round &&
		identification.unallowedCharacters == other.unallowedCharacters &&
		identification.programVersion == other.programVersion

}

func findIdentificationsByWebsite(website string) (identifications []identificationType, err error) {
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
			&identification.round,
			&identification.unallowedCharacters,
			&identification.creationTime,
			&identification.programVersion,
			&identification.note,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}

func findIdentification(website string, user string) (identification identificationType, err error) {
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
			&identification.round,
			&identification.unallowedCharacters,
			&identification.creationTime,
			&identification.programVersion,
			&identification.note,
		)
		if err != nil {
			return identification, err
		}
	}
	return identification, nil
}

func insertIdentification(identification identificationType) (err error) {
	statement, err := database.Prepare("INSERT INTO identifications (website, user, password_length, round, unallowed_characters, creation_time, program_version, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	_, err = statement.Exec(identification.website, identification.user, identification.passwordLength, identification.round, identification.unallowedCharacters, identification.creationTime, identification.programVersion, identification.note)
	return err
}

func searchIdentifications(searchString string) (identifications []identificationType, err error) {
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
			&identification.round,
			&identification.unallowedCharacters,
			&identification.creationTime,
			&identification.programVersion,
			&identification.note,
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
			&identification.round,
			&identification.unallowedCharacters,
			&identification.creationTime,
			&identification.programVersion,
			&identification.note,
		)
		if err != nil {
			return err
		}
		output += strings.Join(identification.toStrings(), ",") + "\n"
	}
	err = ioutil.WriteFile(dir+"/"+tableName+".csv", []byte(output), 0644)
	return err
}

func deleteIdentification(website string, user string) (err error) {
	statement, err := database.Prepare("DELETE FROM identifications WHERE website = ? AND user = ?")
	if err != nil {
		return err
	}
	_, err = statement.Exec(website, user)
	return err
}

func getAllIdentifications() (identifications []identificationType, err error) {
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
			&identification.round,
			&identification.unallowedCharacters,
			&identification.creationTime,
			&identification.programVersion,
			&identification.note,
		)
		if err != nil {
			return nil, err
		}
		identifications = append(identifications, identification)
	}
	return identifications, nil
}
