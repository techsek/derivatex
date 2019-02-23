# derivatex

Smart pseudo-random password generator

[![Derivatex Logo](https://github.com/techsek/derivatex/raw/master/readme/logo.png)](https://github.com/techsek/derivatex)

[![Build Status](https://travis-ci.org/techsek/derivatex.svg?branch=master)](https://travis-ci.org/techsek/derivatex)

[![GitHub last commit](https://img.shields.io/github/last-commit/techsek/derivatex.svg)](https://github.com/techsek/derivatex/commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/y/qdm12/cloudflare-dns-server.svg)](https://github.com/techsek/derivatex/commits)
[![GitHub issues](https://img.shields.io/github/issues/qdm12/cloudflare-dns-server.svg)](https://github.com/techsek/derivatex/issues)

## Features

### Current features

- derivatex uses a *seed* to generate your passwords pseudo-randomly
- **Recovery**: Generate or re-generate the seed `seed.txt` for derivatex deterministically using:
  - your master password
  - your birthdate
  - 1 minute (on a desktop CPU)
  - A computer with more than 512MB of RAM
- derivatex **always** generates the same password for the same (website, user) combination
- **Password security**: derivatex generates a password for each (website, user) combination that:
  - is **different**
  - is **pseudo-random** using the *seed*
  - is **strong** with 128 bits of security
  - **match most website password requirements**
- Default password generation settings produce strong passwords with
  - 20 characters
  - An equal amount of symbols, digits, lowercase letters and uppercase letters
  - A pseudo-random order of characters
- **Adaptable**: Password generation settings **can be changed** for a particular website (i.e. password length, no symbols)
- **Password Management**: Website, user and password generation settings are stored in a local SQLite database in the file `database.sqlite`
- **Export**: The database tables can be dumped to CSV files
- **Portability**: All your password management and generation are contained in 3 files: `derivatex`, `seed.txt` and `database.sqlite`
- **Master password protection**: Argon2ID is used to generate the seed from your master password and birthdate
  - Your master password is protected from its usually low security entropy (output of Argon2ID is a 512 bit key after 1 minute of computation)
  - Your master password or birthdate can't be recovered from the *seed* as Argon2ID is a one-way hash function
- **Resistant to stealing** (to be improved with a server side)
  - An adjective and common noun are randomly picked to encrypt your *seed*
  - The two words are fed to Argon2ID which uses approximately 1 second per try to limit parallel bruteforce attacks (GPUs, FPGAs, ASICs)
  - This forces an attacker to try 10,000 * 170,000 tries = 54 years on a 4 core machine with 512MB of RAM, probably enough time for you to change your passwords.

### Future features

- Golang based server
    - Storing your data encrypted **without** the full decryption key at any time
    - Synchronise your data across all your devices
    - Store half of your seed (to be explored... ideally with a hash through homomorphic encryption)
    - Authentication
        - Google Authenticator and/or Yubikeys
        - Recaptcha v2/v3
        - IP address filtering eventually
        - Email alerts
        - Email + short password
    - Authenticated features
        - Send half of seed temporarily
        - Revoke your seed
        - Add a new device
- User interface app for desktop and mobile in ReactJS or other (Electron?)

## Scheme

![Derivatex diagram](readme/derivatex.svg)

*A few notes*:

- Sign up and log in procedures both require the generation of a password
- Passwords are not saved and only rely on `seed.txt`, you should not save the generated passwords
- The database `database.sqlite` is used to check for existing records and modify them if necessary

## Quick guide

### 1. Download and installation

#### 1.1. Install using `go get`

1. Install [Golang](https://golang.org/dl/)
1. Download and compile the source code from the git repository

    ```bash
    go get -v github.com/techsek/derivatex
    ```

1. The program `derivatex` is now built in `$GOPATH/bin` (or `%GOPATH%/bin` on Windows platforms)

#### 1.2. Build from source

1. Install [Golang](https://golang.org/dl/)
1. Clone the github repository

    ```bash
    git clone https://github.com/techsek/derivatex.git
    cd derivatex
    ```

1. Build derivatex

    ```bash
    go build
    ```

*For the security paranoids...*

- Compile the code with different parameters, see [*params.go*](params.go)
- Do not disclose what program you are using
- Scan the QR code from an offline device i.e. a Raspberry Pi

### 2. Command line interface

1. You might want to move the `derivatex` executable to a safe location, say `/your/safe/path/`
1. Go to `/your/safe/path/`

    ```bash
    cd /your/safe/path/
    ```

1. Create your seed

    ```bash
    derivatex create
    ```

1. Generate your password for *Instagram* and for your default user you have previously set

    ```bash
    derivatex generate instagram
    ```

Keep the **seed.txt** file safe as it serves as the seed to the generation of your passwords.

The file *database.sqlite* is only used to store information about the password generation and is not very sensitive, although it is better to keep it safe.

See more details on how to use derivatex with:

```bash
derivatex help
```

## Details

### Creation of seed.txt (this is being changed)

- Uses Argon2ID with the following parameters:
  - Data is the digest of SHA3_256(password)
  - Salt is the SHA3_256(birthdate) - not good, but better than nothing
  - Time cost is 5000 rounds (takes 10 minutes with a Ryzen 2700x CPU)
  - Memory required is 512MB
  - Parallelism is set to 4 threads
- Resistant to parallel attacks (512MB Memory for 4 processing units)
- Most of computers / phones have 512MB of ram
- Outputs a 512bits key

### Pseudo-random password generation (this is being changed)

- Fast, deterministic and resistant to bruteforce attacks
- Pseudo randomn permutations by using rand.Seed with different source data
- Final password is obtained by:
  - SHA3_256(secretDigest+website name+user)
  - Forcing the first 4 bytes (or less) to be in a pseudo-random order:
    - ASCII lowercase letter
    - ASCII uppercase letter
    - ASCII digit
    - ASCII symbol
  - Forcing the remaining bytes to be in another pseudo-random order one of the 4 ASCII categories shown above

### Password manager

- Each password generation creates a record in a SQLite database containing:
  - Website name
  - User (email, phone number, username), *defaults to the default user set*
  - Password length, *defaults to 20*
  - Round of hash function to generate the password, *defaults to 1*
  - Unallowed characters in the password, *defaults to none*
  - Creation date (automated)
  - Program version (automated) - in case the password generation changes, for backward compatibility
  - Note - an optional text note you can add
- The database can be searched
- The database content can be listed entirely or partially
- Records can be deleted from the database
- A table from the database can be dumped to a CSV file

## Inspiration

- Seeds of Bitcoin wallets
- 12 words seed of Cardano wallets
- Hash functions
- Dashlane password manager
- Trusting no one / paranoia?
- qdm12/hbc
- Palisade and HElib