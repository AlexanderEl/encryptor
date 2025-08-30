package encryptor

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	e := Service{
		PassKey: []byte("test"),
	}
	msg := "super secret message that needs to be encrypted for safe keeping"

	d, err := e.Encrypt([]byte(msg))
	if err != nil {
		t.Errorf("error while encrypting: %s", err)
	}

	v, err := e.Decrypt(d)
	if string(v) != msg {
		t.Errorf("encryption/decryption incorrectly retrieves original message: %s", err)
	}

	e.PassKey = []byte("this is a very long password that should be impossible to predict or guesss as it is impossibly long")
	_, err = e.Encrypt([]byte(msg))
	lengthError := "failed to validate keypass: pass key exceeds maximum length of 32 characters"
	if err != nil && err.Error() != lengthError {
		t.Errorf("unexpected error during encryption of too long key \nError: '%s'\n", err)
	}
}

func TestDecrypt(t *testing.T) {
	e := Service{
		PassKey: []byte("test"),
	}
	encryptedStr := "e2fd61cbe5ddff682e2bc98bf0d92a4c027e38c7b4db10644b65e93823fb56c85d8de0458163b7829fdccc8f8ca5a455758ac4f7fe42f76fc961452b97a49b1eb8b6992ee7d71dbc14e04cf41d951d0127fb1dbd6d2a508fa1f66cf8"
	data, err := hex.DecodeString(encryptedStr)
	if err != nil {
		t.Errorf("failure to decode encrypted string: '%s'", err)
	}

	v, err := e.Decrypt(data)
	if err != nil {
		t.Errorf("unexpected error during decryption: '%s'\n", err)
	}
	expectedOutputStr := "super secret message that needs to be encrypted for safe keeping"
	if string(v) != expectedOutputStr {
		t.Errorf(`invalid decryption str
			expected: '%s'
			actual: '%s'`, expectedOutputStr, v)
	}
}

func TestGeneratePassKey(t *testing.T) {
	e := Service{}
	err := e.GeneratePassKey()
	if err != nil {
		t.Error(err)
	}
	if len(e.PassKey) != 32 {
		t.Errorf("invalid passkey length")
	}

	e2 := Service{}
	_, err = e2.Encrypt([]byte("test"))
	if err != nil {
		t.Error(err)
	}
	if len(e2.PassKey) != 32 {
		t.Errorf("invalid passkey length")
	}
}

func TestPadPassword(t *testing.T) {
	e := Service{
		PassKey: []byte(""),
	}
	pass := e.padPassword()

	if len(pass) != 32 {
		t.Errorf("password is too short - expected: 32 - actual: %d", len(string(pass)))
	}
	if string(pass) != "xXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX" {
		t.Errorf("invalid password padding - actual: %s", string(pass))
	}

	e.PassKey = []byte("Test")
	pass = e.padPassword()

	if len(pass) != 32 {
		t.Errorf("password is too short - expected: 32 - actual: %d", len(string(pass)))
	}
	if string(pass) != "TestxXxXxXxXxXxXxXxXxXxXxXxXxXxX" {
		t.Errorf("invalid password padding - actual: %s", string(pass))
	}
}

func TestInputValidator(t *testing.T) {
	e := Service{}

	pass, err := e.validateInputPassKey()
	if err != nil {
		t.Error(err)
	} else if len(pass) != 32 {
		t.Errorf("invalid passkey length in generation")
	}

	e.PassKey = []byte("12345678901234567890123456789012345678901234567890") // 50 chars
	_, err = e.validateInputPassKey()
	if err != nil && err.Error() != "pass key exceeds maximum length of 32 characters" {
		t.Errorf("expecting max length error")
	}
}

func TestGenerateServiceFromFile(t *testing.T) {
	secureMsg := "very secure message"

	originalService := Service{}
	dataBytes, err := originalService.Encrypt([]byte(secureMsg))
	if err != nil {
		t.Error(err)
	}

	createdService, err := GetEncryptionServiceFromFile("")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(originalService.PassKey, createdService.PassKey) {
		t.Errorf("keys do not match")
	}

	dataBytes, err = createdService.Decrypt(dataBytes)
	if err != nil {
		t.Error(err)
	}

	if string(dataBytes) != secureMsg {
		t.Errorf("failure to decrypt original message")
	}
}
