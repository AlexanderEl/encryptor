package encryptor

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	e := Service{
		WriteKeyToFile: false,
	}
	e.SetPassKey([]byte("test"))
	msg := "super secret message that needs to be encrypted for safe keeping"

	d, err := e.Encrypt([]byte(msg))
	if err != nil {
		t.Errorf("error while encrypting: %s", err)
	}

	v, err := e.Decrypt(d)
	if string(v) != msg {
		t.Errorf("encryption/decryption incorrectly retrieves original message: %s", err)
	}
}

func TestDecrypt(t *testing.T) {
	e := Service{
		WriteKeyToFile: false,
	}
	e.SetPassKey([]byte("test"))

	encryptedHexStr := "e2fd61cbe5ddff682e2bc98bf0d92a4c027e38c7b4db10644b65e93823fb56c85d8de0458163b7829fdccc8f8ca5a455758ac4f7fe42f76fc961452b97a49b1eb8b6992ee7d71dbc14e04cf41d951d0127fb1dbd6d2a508fa1f66cf8"
	data, err := hex.DecodeString(encryptedHexStr)
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
	if len(e.passKey) != 32 {
		t.Errorf("invalid passkey length")
	}

	e2 := Service{}
	_, err = e2.Encrypt([]byte("test"))
	if err != nil {
		t.Error(err)
	}
	if len(e2.passKey) != 32 {
		t.Errorf("invalid passkey length")
	}
}

func TestPadPassword(t *testing.T) {
	e := Service{}

	// Validate empty passkey generation
	e.SetPassKey([]byte(""))
	pass := e.passKey

	if len(pass) != 32 {
		t.Errorf("password is too short - expected: 32 - actual: %d", len(pass))
	}

	// Validate short passkey padding
	e.SetPassKey([]byte("Test"))
	pass = e.passKey

	if len(pass) != 32 {
		t.Errorf("password is too short - expected: 32 - actual: %d", len(pass))
	}
	if string(pass) != "TestxXxXxXxXxXxXxXxXxXxXxXxXxXxX" {
		t.Errorf("invalid password padding - actual: %s", string(pass))
	}
}

func TestSetPassKey(t *testing.T) {
	lengthError := "failed to validate keypass: pass key exceeds maximum length of 32 characters"

	e := Service{}
	newLongKey := []byte("this is a very long password that should be impossible to predict or guesss as it is impossibly long")
	err := e.SetPassKey(newLongKey)

	if err != nil && err.Error() != lengthError {
		t.Errorf("unexpected error during encryption of too long key \nError: '%s'\n", err)
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

	e.SetPassKey([]byte(strings.Repeat("1234567890", 5))) // 50 chars

	_, err = e.validateInputPassKey()
	if err != nil && err.Error() != "pass key exceeds maximum length of 32 characters" {
		t.Errorf("expecting max length error")
	}
	if err == nil {
		t.Errorf("expecting validation error with key being too long")
	}
}

func TestGenerateServiceFromFile(t *testing.T) {
	secureMsg := "very secure message"

	originalService := Service{
		WriteKeyToFile: true,
	}
	dataBytes, err := originalService.Encrypt([]byte(secureMsg))
	if err != nil {
		t.Error(err)
	}

	createdService, err := GetEncryptionServiceFromFile("")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(originalService.passKey, createdService.passKey) {
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

func TestGenerateServiceFromFileDifferentFileName(t *testing.T) {
	secureMsg := "very secure message"

	service := Service{
		WriteKeyToFile: true,
	}
	encryptedData, err := service.Encrypt([]byte(secureMsg))
	if err != nil {
		t.Error(err)
	}

	oldName, newFileName := "passkey.txt", "secureFile.txt"
	err = os.Rename(oldName, newFileName)
	if err != nil {
		t.Error(err)
	}

	newServicePtr, err := GetEncryptionServiceFromFile(newFileName)
	if err != nil {
		t.Error(err)
	}

	decryptedData, err := newServicePtr.Decrypt(encryptedData)
	if err != nil {
		t.Error(err)
	}

	if string(decryptedData) != secureMsg {
		t.Errorf("failure to decrypt data")
	}

	// Clean up the passkey file
	if err = os.Remove(newFileName); err != nil {
		t.Errorf("problem removing passkey file")
	}
}
