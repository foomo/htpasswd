package htpasswd

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func getHashedPasswords() HashedPasswords {
	return HashedPasswords(map[string]string{
		HashBCrypt: "$2y$05$ClsF7kLEDvRXnKnqgYvKnOTq5lLoQ.etyJacxsHO2gGZezPKO/Lua",
		HashSHA5:   "{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY=",
		//test-md5:$apr1$M0Vyedud$k3ny5o2VBoWKsIDRcI53W0
	})
}

func TestHashing(t *testing.T) {
	testHashes := HashedPasswords(make(map[string]string))
	for name, hash := range getHashedPasswords() {
		algo := HashAlgorithm(name)
		err := testHashes.SetPassword(name, name, algo)
		if err != nil {
			t.Fatal(err)
		}
		switch algo {
		case HashSHA5:
			if hash != testHashes[name] {
				t.Fatal("sha fuck up", hash, testHashes[name])
			}
		case HashBCrypt:
			err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(name))
			if err != nil {
				t.Fatal(algo, err)
			}
		}
	}
}
