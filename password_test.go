package password

import (
	"encoding/base64"
	"testing"
)

var validToken = "scrypt$NrpL16384/8/1/32$77v23qUfTy03VLiVqYqYUrZjinTvdvM8JKcqEe8MqpcG0yfzdHk8iMQvoRzM-Naq"

func TestValidLogin(t *testing.T) {
	password := "password"
	token := validToken
	authed, err := Verify(password, token)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if !authed {
		t.Error("Verify was false for valid password-token pair")
	}
}

func TestInvalidLogin(t *testing.T) {
	password := "wrong"
	token := validToken
	authed, err := Verify(password, token)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if authed {
		t.Error("Verify was true for invalid password-token pair")
	}
}

func TestTokenWrongVersion(t *testing.T) {
	password := "password"
	token := "badtoken"
	authed, err := Verify(password, token)
	if err != ErrTokenWrongVersion {
		t.Error("Failed to generate the expected error")
	}
	if authed {
		t.Error("Verify was true for invalid token version")
	}
}

func TestTokenize(t *testing.T) {
	saltedKey := validToken[len(versionHeader):]
	decoded, _ := base64.URLEncoding.DecodeString(saltedKey)
	salt, key := decoded[:18], decoded[18:]
	token := tokenize(salt, key)
	if !compare(token, validToken) {
		t.Error("Tokenize didn't reproduce the expected output")
	}
}

func TestSaltFromToken(t *testing.T) {
	salt, err := saltFromToken(validToken)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if len(salt) != saltLength {
		t.Error("Salt didn't match expected length")
	}
}

func TestRandomSaltNotStatic(t *testing.T) {
	r0, err := createSalt()
	r1 := []byte{}
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	for i := 0; i < 10000; i++ {
		r1, err = createSalt()
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
		if compare(string(r0), string(r1)) {
			t.Error("Successive random values were equal")
		} else {
			r0 = r1
		}
	}
}

func TestHash(t *testing.T) {
	token, err := Hash("password")
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	authed, err := Verify("password", token)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
	if !authed {
		t.Error("Verify was false for valid password-token pair")
	}
}

func TestExcessivePasswordLength(t *testing.T) {
	password := string(make([]byte, 2048))
	_, err := Hash(password)
	if err != ErrPasswordLength {
		t.Error("Failed to generate the expected error")
	}
	_, err = Verify(password, "faketoken")
	if err != ErrPasswordLength {
		t.Error("Failed to generate the expected error")
	}
}
