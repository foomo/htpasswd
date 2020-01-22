package htpasswd

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/GehirnInc/crypt/apr1_crypt"
	"golang.org/x/crypto/bcrypt"
)

func poe(err error) {
	if err != nil {
		panic(err)
	}
}

func getHashedPasswords() HashedPasswords {
	return HashedPasswords(map[string]string{
		HashAPR1:   "$apr1$qxYNc6nQ$yp9F.jioKu3yR3T7fvXYs.",
		HashBCrypt: "$2y$05$ClsF7kLEDvRXnKnqgYvKnOTq5lLoQ.etyJacxsHO2gGZezPKO/Lua",
		HashSHA:    "{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY=",
	})
}

func tFile(name string) string {
	f, err := ioutil.TempFile(os.TempDir(), "foomo-htpasswd-test-"+name)
	poe(err)
	return f.Name()
}

func fileContentsAre(t *testing.T, file string, contents string) {
	fileBytes, err := ioutil.ReadFile(file)
	poe(err)
	if contents != string(fileBytes) {
		t.Fatal("unexpected file contents", "should have been", contents, "was \""+string(fileBytes)+"\"")
	}
}

func TestParseHtpassd(t *testing.T) {
	passwords, err := ParseHtpasswd([]byte("sha:{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY=\n"))
	poe(err)
	if len(passwords) != 1 {
		t.Fatal("unexpected length in passwords")
	}
	const expected = "{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY="
	if passwords["sha"] != expected {
		t.Fatal("sha password was wrong", passwords["sha"], "but expected", expected)
	}
}

func TestEmptyHtpasswdFile(t *testing.T) {
	f := tFile("empty")
	SetPassword(f, "sha", "sha", HashSHA)
	fileContentsAre(t, f, "sha:{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY=\n")
}

func TestRemoveUser(t *testing.T) {
	f := tFile("removeUser")
	const firstUser = "sha"
	SetPassword(f, firstUser, "sha", HashSHA)
	const user = "foo"
	SetPassword(f, user, "bar", HashBCrypt)
	RemoveUser(f, user)
	fileContentsAre(t, f, "sha:{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY=\n")
	passwordsFromFile, err := ParseHtpasswdFile(f)
	poe(err)
	if passwordsFromFile[firstUser] != "{SHA}2PRZAyDhNDqRW2OUFwZQqPNdaSY=" {
		t.Fatal("failed to read right data from manipulated file")
	}

	if err := RemoveUser(f, "doesnotexist"); err != ErrNotExist {
		t.Fatal("error returned when user does not exist is not ErrNotExist")
	}
}

func TestCorruption(t *testing.T) {
	hasToE := func(err error, topic string) {
		if err == nil {
			t.Fatal("missed to get an error for", topic)
		}
	}
	const (
		corruptLine       = "foo:bar:bu\n"
		corruptRepeatUser = "foo:pwd\nbar:bla\nfoo:fooagain\n"
	)
	_, eLine := ParseHtpasswd([]byte(corruptLine))
	_, eUser := ParseHtpasswd([]byte(corruptRepeatUser))
	hasToE(eLine, "corrupt line")
	hasToE(eUser, "corrupt user repetition")
}

func TestSetPasswordHash(t *testing.T) {
	f := tFile("set-hashes")
	poe(SetPasswordHash(f, "a", "a"))
	poe(SetPasswordHash(f, "b", "b"))
	poe(SetPasswordHash(f, "c", "c"))
	poe(RemoveUser(f, "b"))
	passwords, err := ParseHtpasswdFile(f)
	poe(err)
	if passwords["a"] != "a" {
		t.Fatal("a failed")
	}
	if passwords["b"] != "" {
		t.Fatal("b failed")
	}
	if passwords["c"] != "c" {
		t.Fatal("c failed")
	}
}
func TestVerifyPasswordInFile(t *testing.T) {
	f := tFile("verify-hash")
	SetPassword(f, "sha", "sha", HashSHA)
	ok, err := VerifyPassword(f, "sha", "sha", HashSHA)
	poe(err)
	if !ok {
		t.Fatal("Hash in file verify failed")
	}
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
		case HashAPR1:
			err := apr1_crypt.New().Verify(hash, []byte(name))
			if err != nil {
				t.Fatal(algo, hash, testHashes[name])
			}
		case HashSHA:
			if hash != testHashes[name] {
				t.Fatal(algo, hash, testHashes[name])
			}
		case HashBCrypt:
			err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(name))
			if err != nil {
				t.Fatal(algo, err)
			}
		}
	}
}

func TestVerify(t *testing.T) {
	testHashes := getHashedPasswords()
	for _, algo := range HashAlgorithms {
		if !testHashes.VerifyPassword(string(algo), string(algo), algo) {
			t.Error(algo, testHashes[string(algo)])
		}
	}
}
