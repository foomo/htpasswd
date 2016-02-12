package htpasswd

import (
	"errors"
	"io/ioutil"
	"strings"
)

// HashedPasswords name => hash
type HashedPasswords map[string]string

// HashAlgorithm enum for hashing algorithms
type HashAlgorithm string

const (
	// HashBCrypt bcrypt - recommended
	HashBCrypt = "bcrypt"
	// HashSHA5 sha5 insecure - do not use
	HashSHA5 = "sha5"
)

const (
	// PasswordSeparator separates passwords from hashes
	PasswordSeparator = ":"
	// LineSeparator separates password records
	LineSeparator = "\n"
)

// MaxHtpasswdFilesize if your htpassd file is larger than 8MB, then your are doing it wrong
const MaxHtpasswdFilesize = 8 * 1024 * 1024 * 1024

// Bytes bytes representation
func (hp HashedPasswords) Bytes() (passwordBytes []byte) {
	passwordBytes = []byte{}
	for name, hash := range hp {
		passwordBytes = append(passwordBytes, []byte(name+PasswordSeparator+hash+LineSeparator)...)
	}
	return passwordBytes
}

// WriteToFile put them to a file will be overwritten or created
func (hp HashedPasswords) WriteToFile(file string) error {
	return ioutil.WriteFile(file, hp.Bytes(), 0644)
}

// SetPassword set a password for a user with a hashing algo
func (hp HashedPasswords) SetPassword(name, password string, hashAlgorithm HashAlgorithm) (err error) {
	hash := ""
	prefix := ""
	switch hashAlgorithm {
	case HashBCrypt:
		prefix = "$2y$"
		hash, err = hashBcrypt(password)
	case HashSHA5:
		prefix = "{SHA}"
		hash = hashSha(password)
	}
	if err != nil {
		return err
	}
	hp[name] = prefix + hash
	return nil
}

// ParseHtpasswdFile load a htpasswd file
func ParseHtpasswdFile(file string) (passwords HashedPasswords, err error) {
	htpasswdBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	if len(htpasswdBytes) > MaxHtpasswdFilesize {
		err = errors.New("this file is too large, use a database instead")
		return
	}
	return ParseHtpasswd(htpasswdBytes)
}

// ParseHtpasswd parse htpasswd bytes
func ParseHtpasswd(htpasswdBytes []byte) (passwords HashedPasswords, err error) {
	lines := strings.Split(LineSeparator, string(htpasswdBytes))
	passwords = make(map[string]string)
	for _, line := range lines {
		// scan lines
		line = strings.Trim(line, " ")
		if len(line) == 0 {
			// skipping empty lines
			continue
		}
		parts := strings.Split(PasswordSeparator, line)
		for i, part := range parts {
			parts[i] = strings.Trim(part, " ")
		}
	}
	return
}

// SetHtpasswdHash set password hash for a user
func SetHtpasswdHash(file, name, hash string) error {
	passwords, err := ParseHtpasswdFile(file)
	if err != nil {
		return err
	}
	passwords[name] = hash
	return passwords.WriteToFile(file)
}

// SetPassword set password for a user with a given hashing algorithm
func SetPassword(file, name, password string, hashAlgorithm HashAlgorithm) error {
	passwords, err := ParseHtpasswdFile(file)
	if err != nil {
		return err
	}
	err = passwords.SetPassword(name, password, hashAlgorithm)
	if err != nil {
		return err
	}
	return passwords.WriteToFile(file)
}
