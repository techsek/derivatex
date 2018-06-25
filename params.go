package main

// Only used to reconstruct master digest from master password and birthdate
const argonMemoryMB uint32 = 2048 // the more the better, depending on your machine
const argonDigestSize uint32 = 64
const argonTimeCost uint32 = 130
const argonParallelism uint8 = 1
const argonTestRounds uint32 = 1

const masterDigestFilename = "secret_digest.txt"
const defaultPasswordLength = 20
const databaseFilename = "database"
const defaultTableToDump = "identifications"

const version = 1

const (
	symbols    = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	digits     = "0123456789"
	lowercases = "abcdefghijklmnopqrstuvwxyz"
	uppercases = "ABCDEFGHIKLMNOPQRSTVXYZ"
)
