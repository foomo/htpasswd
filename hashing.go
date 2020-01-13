package htpasswd

import (
	"crypto/sha1"
	"encoding/base64"

	"github.com/GehirnInc/crypt/apr1_crypt"
	"golang.org/x/crypto/bcrypt"
)

func hashApr1(password string) (string, error) {
	return apr1_crypt.New().Generate([]byte(password), nil)
}

func hashSha(password string) string {
	s := sha1.New()
	s.Write([]byte(password))
	passwordSum := []byte(s.Sum(nil))
	return base64.StdEncoding.EncodeToString(passwordSum)
}

func hashBcrypt(password string) (hash string, err error) {
	passwordBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	return string(passwordBytes), nil
}
