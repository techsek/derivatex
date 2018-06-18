package main

import (
	"database/sql"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
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
		"CREATE TABLE IF NOT EXISTS identifiants (website TEXT, user TEXT, password_length INTEGER, unix_time INTEGER, round INTEGER, version INTEGER, PRIMARY KEY(website, user))")
	if err != nil {
		return err
	}
	_, err = statement.Exec()
	if err != nil {
		return err
	}
	return nil
}

type identifiantType struct {
	website        string
	user           string
	passwordLength int
	unixTime       int64
	round          int
	version        uint16
}

func (identifiant *identifiantType) toString() string {
	return identifiant.website + "," + identifiant.user + "," + strconv.FormatInt(int64(identifiant.passwordLength), 10) + "," +
		strconv.FormatInt(identifiant.unixTime, 10) + "," + strconv.FormatInt(int64(identifiant.round), 10) + "," + strconv.FormatUint(uint64(identifiant.version), 10)
}

func findIdentifiantsByWebsite(website string) (identifiants []identifiantType, err error) {
	statement, err := database.Prepare("SELECT website, user, password_length, unix_time, round, version FROM identifiants WHERE website = ?")
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query(website)
	if err != nil {
		return nil, err
	}
	var identifiant identifiantType
	for rows.Next() {
		err = rows.Scan(
			&identifiant.website,
			&identifiant.user,
			&identifiant.passwordLength,
			&identifiant.unixTime,
			&identifiant.round,
			&identifiant.version,
		)
		if err != nil {
			return nil, err
		}
		identifiants = append(identifiants, identifiant)
	}
	return identifiants, nil
}

func findIdentifiant(website string, user string) (identifiant identifiantType, err error) {
	statement, err := database.Prepare("SELECT website, user, password_length, unix_time, round, version FROM identifiants WHERE website = ? AND user = ?")
	if err != nil {
		return identifiant, err
	}
	rows, err := statement.Query(website, user)
	if err != nil {
		return identifiant, err
	}
	if rows.Next() {
		err = rows.Scan(
			&identifiant.website,
			&identifiant.user,
			&identifiant.passwordLength,
			&identifiant.unixTime,
			&identifiant.round,
			&identifiant.version,
		)
		if err != nil {
			return identifiant, err
		}
	}
	return identifiant, nil
}

func insertIdentifiant(website string, user string, passwordLength int, round int) (err error) {
	statement, err := database.Prepare("INSERT INTO identifiants (website, user, password_length, unix_time, round, version) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	_, err = statement.Exec(website, user, passwordLength, time.Now().Unix(), round, version)
	return err
}

func searchIdentifiants(searchString string) (identifiants []identifiantType, err error) {
	statement, err := database.Prepare("SELECT website, user, password_length, unix_time, round, version FROM identifiants WHERE website LIKE ? OR user LIKE ?")
	if err != nil {
		return nil, err
	}
	rows, err := statement.Query("%"+searchString+"%", "%"+searchString+"%")
	if err != nil {
		return nil, err
	}
	var identifiant identifiantType
	for rows.Next() {
		err = rows.Scan(
			&identifiant.website,
			&identifiant.user,
			&identifiant.passwordLength,
			&identifiant.unixTime,
			&identifiant.round,
			&identifiant.version,
		)
		if err != nil {
			return nil, err
		}
		identifiants = append(identifiants, identifiant)
	}
	return identifiants, nil
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
	var identifiant identifiantType
	output := "Website,User,Password Length,Unix Time,Round,Program version\n"
	for rows.Next() {
		err = rows.Scan(
			&identifiant.website,
			&identifiant.user,
			&identifiant.passwordLength,
			&identifiant.unixTime,
			&identifiant.round,
			&identifiant.version,
		)
		if err != nil {
			return err
		}
		output += identifiant.toString() + "\n"
	}
	err = ioutil.WriteFile(dir+"/"+tableName+".csv", []byte(output), 0644)
	return err
}
