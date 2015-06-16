package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"fmt"
	"golang.org/x/crypto/scrypt"
)

// Parameters for scrypt key derivation, appropriate for interactive login.
const n = 16384
const r = 8
const p = 1

// Length of the salt. Reasonable secure value is 128-bit / 16-byte.
const saltLength = 16

// Length of the scrypt derived key.
const keyLength = 32

// Prepend this to tokens to support future upgrades of the hashing function.
var versionHeader = fmt.Sprintf("scrypt$NrpL%d/%d/%d/%d$", n, r, p, keyLength)

// ErrTokenWrongVersion is generated if a token's versionHeader doesn't match
var ErrTokenWrongVersion = errors.New("Token header did not match current version.")

// ErrPasswordLength is generated if a password is greater than 1024 bytes
var ErrPasswordLength = errors.New("Password longer than 1 KB, refused as denial of service safeguard.")

// Compare strings via bitwise XOR, i.e. constant-time comparison
func compare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Tokenize the salt and salted hash key
func tokenize(salt, key []byte) string {
	return versionHeader + base64.StdEncoding.EncodeToString(append(salt, key...))
}

// Verify that a token is plausible and extract the salt stored in a token
func saltFromToken(token string) ([]byte, error) {
	if !compare(token[:len(versionHeader)], versionHeader) {
		return nil, ErrTokenWrongVersion
	}
	decoded, err := base64.StdEncoding.DecodeString(token[len(versionHeader):])
	if err != nil {
		return nil, err
	}
	return decoded[:saltLength], nil
}

// Generate cryptographically-sound random salt via crypto/rand
func createSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt[:cap(salt)])
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// Calculate scrypt salted hash key from password and salt
func createKey(password string, salt []byte) []byte {
	key, err := scrypt.Key([]byte(password), salt, n, r, p, keyLength)
	if err != nil {
		log.Fatal(err.Error())
	}
	return key
}

// Hash returns a destructive cryptographic hash of the provided password
func Hash(password string) (string, error) {
	if len(password) > 1024 {
		return "", ErrPasswordLength
	}
	salt, err := createSalt()
	if err != nil {
		return "", err
	}
	key := createKey(password, salt)
	return tokenize(salt, key), nil
}

// Verify that password is consistent with token
func Verify(password, token string) (bool, error) {
	if len(password) > 1024 {
		return false, ErrPasswordLength
	}
	salt, err := saltFromToken(token)
	if err != nil {
		return false, err
	}
	key := createKey(password, salt)
	return compare(tokenize(salt, key), token), nil
}
