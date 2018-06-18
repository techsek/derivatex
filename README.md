# Derivatex

Password derivator using hash functions written in Golang

**WORK IN PROGRESS**

## TODOS

### Urgent

1. No symbol options etc. in database
1. Unit testing
1. Finish readme and diagrams

### Later

- Time shown in human readable format
- Preferences (file and interactive)
  - Default search Exlusive or not
  - Smaller QR code
  - CSV separator
- Yubikeys / Google Authenticator
- Generate private keys i.e. RSA
- Better search

## Features

- Protects your password from many type of attacks
  - Parallel bruteforce attacks using GPUs, FPGAs, ASICs
  - Quantum cracking (uses Argon2ID and SHA3 256) - except for AES encryption with PIN code
- Password manager features
- Configurable
- Extensive unit testing for solid security
- No web, no 3rd party, all in your hands
- Minimal memory footprint for security purposes using pointers for all sensitive data
- Multiple rounds of generation for change password requirement
- Dump Database tables to CSV files

## Overview of security scheme

TODO

See more details below

## How to use

1. Create master digest interactively
1. Generate passwords with:
  - Optional flags
1. Check on which websites you created a password

## Password key derivation

- Uses Argon2ID with the following parameters:
  - Data is the digest of SHA3_256(password)
  - Salt is the SHA3_256(birthdate)
  - Time cost is 500 rounds (takes 4 minutes on the quad core machine)
  - Memory required is 2048MB
  - Parallelism is set to 1 thread
- Resistant to parallel attacks (2048MB Memory per processing unit)
- Most of computers / phones have 2048MB of ram
- Outputs a 512bits key

## Passwords generation

- Fast, deterministic and resistant to bruteforce attacks
- Pseudo randomn permutations by using rand.Seed with different source data
- Final password is:
  - Strong (high entropy)
  - 20 characters long by default
  - Contains different character type to match requirements of most websites
- Final password is obtained by:
  - SHA3_256(secretDigest+name)
  - Forcing the first 4 bytes (or less) to be in a pseudo-random order:
    - ASCII lowercase alphabetic
    - ASCII uppercase alphabetic
    - ASCIIdigit
    - ASCII symbol
  - Forcing the remaining bytes to be in another pseudo-random order one of the 4 ASCII categories shown above

## Password manager

- Each password generation creates a record in a SQLite database containing:
  - website name
  - identifiant (email, phone number, username)
  - Password Length (in case a certain length was required)
- This database can be searched and the password can be generated again
- The database can be dumped into a text file

## For the security paranoids

- Compile the code with different parameters
- Compile with Docker
- Do not disclose what program you are using
- Scan the QR code from an offline device
