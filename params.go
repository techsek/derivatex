package main

// Only used to reconstruct master digest from master password and birthdate
const argonMemoryMB uint32 = 2048
const argonDigestSize uint32 = 64
const argonTimeCost uint32 = 500
const argonParallelism uint8 = 4
const argonTestRounds uint32 = 14

const masterDigestFilename = "secret_digest.txt"
const defaultPasswordLength = 20
const identifiantsFilename = "identifiants.csv"
