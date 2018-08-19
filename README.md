# derivatex

Smart pseudo-random password generator

[![Derivatex Logo](https://github.com/techsek/derivatex/raw/master/readme/logo.png)](https://github.com/techsek/derivatex)

[![Build Status](https://travis-ci.org/techsek/derivatex.svg?branch=master)](https://travis-ci.org/techsek/derivatex)

[![GitHub last commit](https://img.shields.io/github/last-commit/techsek/derivatex.svg)](https://github.com/techsek/derivatex/commits)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/y/qdm12/cloudflare-dns-server.svg)](https://github.com/techsek/derivatex/commits)
[![GitHub issues](https://img.shields.io/github/issues/qdm12/cloudflare-dns-server.svg)](https://github.com/techsek/derivatex/issues)

*Stable and will stay backward compatible (hopefully)*

**Keep your seed.txt and database.sqlite files safe !!!**

## Features

### Current features

- derivatex uses a *seed* to generate your passwords and keys pseudo-randomly
- **Recovery**: Generate or re-generate the seed `seed.txt` for derivatex deterministically using:
  - your master password
  - your birthdate
  - 10 minutes (on a desktop CPU)
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
- **Password Management**: Website, user and password generation settings are stored in a SQLite database in the file `database.sqlite`
- **Export**: The database tables can be dumped to CSV files
- **Portability**: All your password management and generation are contained in 3 files: `derivatex`, `seed.txt` and `database.sqlite`
- **Master password protection**: Argon2ID is used to generate the seed from your master password and birthdate
  - Your master password is protected from its usually low security entropy (output of Argon2ID is a 512 bit key after 10 minutes)
  - Your master password or birthdate can't be recovered from the *seed* as Argon2ID is a one-way hash function
- **Resistant to stealing**
  - An adjective and common noun are randomly picked to encrypt your *seed*
  - The two words are fed to Argon2ID which uses approximately 1 second per try to limit parallel bruteforce attacks (GPUs, FPGAs, ASICs)
  - This forces an attacker to try 10,000 * 170,000 tries = 54 years on a 4 core machine with 512MB of RAM, probably enough time for you to change your passwords.

### Future features

- **E2EE storage**: Store your `database.sqlite` and `seed.txt` with end-to-end encryption
- **Revokation**: Revoke your *seed* using a server and homomorphic encryption (see future scheme below)
- **2F auth**: Use Google Authenticator and/or Yubikeys
- **IP filtering**: Ask for 2F auth if the IP is not the usual IP address to block hackers or stealers
- **Email alerting**: Send one way email alerts when your server seed is accessed by a new IP address for example
- **Privacy preserved**: The server has only access to one of the 2 seeds and computes your passwords with homomorphic encryption. The server never knows your passwords or the full seed.

## Scheme

### Current scheme

![Derivatex diagram](readme/derivatex.svg)

*A few notes*:

- Sign up and log in procedures both require the generation of a password
- Passwords are not saved and only rely on `seed.txt`, you should not save the generated passwords
- The database `database.sqlite` is used to check for existing records and modify them if necessary

### Future scheme

- **Creation stage**:
  1. Generate the seed `S` using Argon2ID, your master password and birthdate as before
  1. Split `S` in two halves `S1` and `S2`
  1. Send `S2` to our server
  1. Delete `S` and `S2` permanently from local device
- **Generation stage**: To generate a password for the website `cryptoblog` and the user `alice`:
  1. Produce the digest `D` = SHA3_256(`cryptoblog`+`alice`)
  1. Generate a keypair (`privKey`, `pubKey`) for homomorphic encryption (or use a pre-generated one)
  1. Encrypt `S1` with `pubKey` to give `Enc(S1)`
  1. Encrypt `D` with `pubKey` to give `Enc(D)`
  1. Send `pubKey`, `Enc(D)`, and `Enc(S1)` to our server
  1. Our server encrypts its seed half `S2` with `pubKey` to give `Enc(S2)`
  1. Our server computes the digest of SHA3_256(S1+S2+D) using homomorphic encryption
  1. Our server sends back the encrypted digest `Enc(password)`
  1. Decrypt `Enc(password)` using `privKey` to provide `password`
  1. Force `password` (just bytes) to match the password requirements (i.e. ASCII with no symbols)

With this scheme, many new features are then available:

- **Revokation**: Revoke your *seed* through the server
- **2F auth**: Use Google Authenticator and/or Yubikeys
- **IP filtering**: Ask for 2F auth if the IP is not the usual IP address to block hackers or stealers
- **Email alerting**: Send one way email alerts when your server seed is accessed by a new IP address for example
- **Privacy preserved**: The server has only access to one of the 2 seeds and computes your passwords with homomorphic encryption. The server never knows your passwords or the full seed.

The only way an attacker *Eve* can be successful is to access our server **and** your device, which is quite unlikely.
Note that more servers could be added by splitting the seed in more parts or even using *secret sharing*.

## Other security aspects

- Extensive unit testing for solid security (TODO)
- Minimal memory footprint of sensitive data using pointers for byte arrays

## Resistance

Let's assume *Eve* is the attacker, and *www.terriblewebsite.com* is a website having bad security systems.

The following list of situations goes from most likely to happen to most unlikely to happen.

- **Situation**: *Eve* hacks the database of *www.terriblewebsite.com* which stores passwords in plaintext
  - **Damage**: *Eve* has access to your account at *www.terriblewebsite.com* only
  - **Resistance**: *Eve* can't access other websites you are registered at (*each password generated is unique*)
  - **Resistance**: The *seed.txt* file can't be obtained from the password (*password is derived using the SHA3 256 hash function* - even quantum bruteforcing would fail)
  - **Intervention**: Generate another password for *www.terriblewebsite.com* using the option flag `-round=2` (or more) and change your password on *www.terriblewebsite.com*
- **Situation**: *Eve* knows your username and tries to bruteforce your account on *www.terriblewebsite.com*
  - **Resistance**: Using default settings (or similar or better), *Eve* will need centuries to bruteforce successfully the password
  - **Intervention**: None
- **Situation**: *Eve* obtains your *database.sqlite* and *derivatex* files
  - **Damage**: *Eve* knows
    - The websites you are registered on with what user
    - Your password generation settings for each website (i.e. password length)
  - **Resistance**: *Eve* does not have your passwords and can't find them unless they were generated with very poor security settings (i.e. only digits with length 4)
  - **Intervention**: None
- **Situation**: *Eve* obtains your *seed.txt*, *database.sqlite* and *derivatex* files
  - **Damage**: *Eve* knows
    - The websites you are registered on with what user
    - Your password generation settings for each website (i.e. password length)
    - She can re-generate your passwords IFF:
      - **FUTURE FEATURE**: She uses your usual IP address / machine OR has access to your 2F auth
      - **FUTURE FEATURE**: You did not revoke the server seed yet
  - **Resistance**:
    - *Eve* can't recover your master password or birthdate (Argon2id)
    - **FUTURE FEATURE** *Eve* can be blocked and asked for your 2F Auth if she uses a machine with an IP address different from your usual IP addresses
    - **FUTURE FEATURE** *Eve* will not be able to generate passwords as soon as the server seed is revoked
  - **Intervention**: Change your master password, re-generate a seed and change all your passwords
- **Situation**: *Eve* knows your birthdate **and** master password
  - **Damage**: *Eve* generates your *seed.txt* and can generate any password
  - **Resistance**: *Eve* does not know on which website you are registered and which password settings you used
  - **Intervention**: Change your master password, re-generate a seed and change all your passwords

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
1. Install [dep](https://golang.github.io/dep/docs/installation.html) for dependency management
1. Clone the github repository in your `$GOPATH`

    ```bash
    git clone https://github.com/techsek/derivatex.git $GOPATH/src/github.com/techsek/derivatex
    ```

1. Build derivatex

    ```bash
    cd $GOPATH/src/github.com/techsek/derivatex
    dep ensure
    go build
    ```

*For the security paranoids...*

- Compile the code with different parameters, see [*params.go*](params.go)
- Compile with Docker and run with Docker
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

## TO DOs

### Urgent

- [ ] Rework code with future server in mind
  - [ ] Split secret digest into 2 256-bit halves
  - [ ] Do SHA 256 of (website+user)
- [ ] Rework code for language portability
  - [ ] Understand rand.Seed or use something else in password generation
- [ ] Show age in days instead of creation time
- [ ] Interactive CLI command choice when no argument is provided
- [ ] Encrypt database locally with passphrase if set
- [ ] Log file
- [x] Replace PIN code with 2 random words passphrase with Argon2id
- [ ] Rework CLI with [urface/cli](https://github.com/urfave/cli)

### Documentation

- [ ] Roadmap
- [ ] Add diagram to explain how to generate passwords for signup and login
- [ ] Diagram on Banana Split
- [x] Make logo, maybe with ASCII art?
- [ ] Add Github Markdown badges to readme
  - [x] Travis CI build
  - [ ] Unit testing code coverage
  - [ ] Docker hub build / Travis docker build
  - [x] Last commit
  - [x] Commit activity
  - [x] Issues
  - [ ] Docker pulls
  - [ ] Docker stars
  - [ ] Docker build automated
  - [ ] Docker image size and layers
  - [ ] Version
- [ ] Github wiki
  - [ ] CLI
- [ ] Donation button
  - [ ] Bitcoin
  - [ ] Ethereum
  - [ ] Ada (haha)
  - [ ] Paypal

### CLI

- [ ] Fix different drive paths on Windows platform
- [ ] Flag to choose the CSV separator when dumping a table
- [ ] Make search command work with multiple words separated by space
- [ ] Generate seed words (i.e. 12 words for cardano)
- [ ] Generate SSH keys
- [ ] Calculate and display entropy of final password
- [ ] Preferences file
  - [ ] Default search: Exlusive or not
  - [ ] Size of ASCII QR code

### Core client code

- [ ] Database migrations?
- [ ] *LATER* Write more unit tests

### Server

- [ ] End-to-end encrypted and synced storage
  - [ ] Identifications database
  - [ ] Log file
- [ ] Log in to server using password (maybe 2 same words?) with Google Authenticator or Yubikey
  - [ ] Google Authenticator: Use the SHA(seed[:32]) as the seed (or something else depending on revoke feature)
  - [ ] Yubikey
  - [ ] Some secret sharing ? More servers?
- [ ] Homomorphic encryption
  - [ ] Revoke feature by deleting the half seed S2 on the server
  - [ ] Revoke and replace feature would be great?
  - [ ] IP filtering, email alerts
  - [ ] Use [Palisade](https://git.njit.edu/palisade/PALISADE/wikis/Use-The-Library) or stick to HElib?

### UI

- [ ] Computer UI
- [ ] Mobile UI

### Distribution

- [x] Travis CI automated build with testing
- [x] Pre-built binaries for all computer platforms (not mobile)
- [ ] Docker image for the CLI
- [ ] Docker image for the server

## Cutting a new release

When you're ready to release, ensure you are on the master branch:

1. Create a tag and specify a version number (see [here](https://semver.org/) for info on semantic versioning)

    ```bash
    git tag -a 0.1.0 -m "short tagging message"
    ```

1. Push the tag up

    ```bash
    git push origin 0.1.0
    ```

That's it! TravisCI takes care of creating all the assets.

See [keepachangelog.com](https://keepachangelog.com/en/1.0.0/) for more good habits

## Inspiration

- Seeds of Bitcoin wallets
- 12 words seed of Cardano wallets
- Hash functions
- Dashlane password manager
- Trusting no one / paranoia?
- qdm12/hbc
- Palisade and HElib