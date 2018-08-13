package constants

// Only used to reconstruct master digest from master password and birthdate
const ArgonMemoryMB uint32 = 2048 // the more the better, depending on your machine
const ArgonDigestSize uint32 = 64
const ArgonTimeCost uint32 = 130
const ArgonParallelism uint8 = 1
const ArgonTestRounds uint32 = 1

const MasterDigestFilename = "secret_digest.txt"
const DefaultPasswordLength = 20
const DatabaseFilename = "database"
const DefaultTableToDump = "identifications"

const Version = 2

const (
	Symbols    = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	Digits     = "0123456789"
	Lowercases = "abcdefghijklmnopqrstuvwxyz"
	Uppercases = "ABCDEFGHIKLMNOPQRSTVXYZ"
)
