package constants

// Only used to reconstruct seed from master password and birthdate
const ArgonMemoryMB uint32 = 512 // the more the better, depending on your machine
const ArgonDigestSize uint32 = 64
const ArgonTimeCost uint32 = 5000
const ArgonParallelism uint8 = 4
const ArgonTestRounds uint32 = 100

// Argon2ID settings for the optional passphrase to encrypt the seed
const PassphraseArgonMemoryMB uint32 = 100
const PassphraseArgonDigestSize uint32 = 32
const PassphraseArgonTimeCost uint32 = 10
const PassphraseArgonParallelism uint8 = 4

const SeedFilename = "seed.txt"
const DefaultPasswordLength = 20
const DatabaseFilename = "database.sqlite"
const DefaultTableToDump = "identifications"

const PasswordDerivationVersion = 2

const (
	Symbols    = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	Digits     = "0123456789"
	Lowercases = "abcdefghijklmnopqrstuvwxyz"
	Uppercases = "ABCDEFGHIKLMNOPQRSTVXYZ"
)
