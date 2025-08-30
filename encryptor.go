package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

type Encryptor interface {
	// Encrypt input bytes using AES-256, returning encrypted bytes or error
	Encrypt(data []byte) ([]byte, error)

	// Decrypt intput bytes, returning decrypted bytes or error
	Decrypt(data []byte) ([]byte, error)

	// A helper method for generating a maximum length, randomized passkey
	GeneratePassKey() error

	GetEncryptionServiceFromFile(filePath string) (*Service, error)
}

type Service struct {
	// The passKey key that will be used in the encryption
	// Mandatory field for decryption - can be loaded via key file
	PassKey []byte
}

var passwordByteLength int = 32
var passKeyFileName string = "passkey.txt"

func (s *Service) Encrypt(data []byte) ([]byte, error) {
	passKey, err := s.validateInputPassKey()
	if err != nil {
		return nil, fmt.Errorf("failed to validate keypass: %s", err)
	}

	aesCipher, err := aes.NewCipher(passKey)
	if err != nil {
		return nil, fmt.Errorf("failure to create new cipher for encryption: %s", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failure to create new GCM: %s", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failure to populate nonce during encryption: %s", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (s *Service) validateInputPassKey() ([]byte, error) {
	length := len(s.PassKey)
	if length > passwordByteLength {
		return nil, fmt.Errorf("pass key exceeds maximum length of 32 characters")
	} else if length == 0 {
		err := s.GeneratePassKey()
		return s.PassKey, err
	}
	return s.padPassword(), nil
}

func (s *Service) padPassword() []byte {
	passLength := len(s.PassKey)
	if passLength == passwordByteLength {
		return s.PassKey
	}

	password := make([]byte, passwordByteLength)
	for i := range passwordByteLength {
		if i < passLength {
			password[i] = s.PassKey[i]
		} else if i%2 == 0 {
			password[i] = 'x'
		} else {
			password[i] = 'X'
		}
	}
	return password
}

func (s *Service) Decrypt(data []byte) ([]byte, error) {
	passKey, err := s.validateInputPassKey()
	if err != nil {
		return nil, fmt.Errorf("failed to validate keypass: %s", err)
	}

	aesCipher, err := aes.NewCipher(passKey)
	if err != nil {
		return nil, fmt.Errorf("failure to create new cipher for decryption: %s", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failure to create new GCM: %s", err)
	}

	cipher, nonce := data[gcm.NonceSize():], data[:gcm.NonceSize()]

	plain, err := gcm.Open(nil, nonce, cipher, nil)
	if err != nil {
		return nil, fmt.Errorf("failure to decrypt data: %s", err)
	}

	return plain, nil
}

func (s *Service) GeneratePassKey() error {
	passKey := make([]byte, passwordByteLength)
	numBytes, err := rand.Read(passKey)
	if err != nil {
		return fmt.Errorf("failure to generate random passkey: %s", err)
	} else if numBytes != passwordByteLength {
		return fmt.Errorf("only %d characters generated rather than the full length", numBytes)
	}

	s.PassKey = passKey // set the newly created passkey

	encodedPassKey := make([]byte, hex.EncodedLen(len(passKey)))
	hex.Encode(encodedPassKey, passKey)

	if err := os.WriteFile(passKeyFileName, encodedPassKey, 0644); err != nil {
		return fmt.Errorf("error while writing generated passkey to file: %s", err)
	}

	return nil
}

// Create Encryption service from passkey file
// Will check current directory or provided file path (optional)
func GetEncryptionServiceFromFile(filePath string) (*Service, error) {
	path := passKeyFileName
	if filePath != "" {
		path = filePath
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("passkey file does not exist in current directory")
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failure to read passkey file content with error: %s", err)
	}

	passKeyBytes := make([]byte, hex.DecodedLen(len(bytes)))
	numBytesDecoded, err := hex.Decode(passKeyBytes, bytes)

	if err != nil {
		return nil, fmt.Errorf("failure to read passkey bytes with error: %s", err)
	} else if numBytesDecoded != hex.DecodedLen(len(bytes)) {
		return nil, fmt.Errorf("failure to decode all bytes with error: %s", err)
	}

	return &Service{
		PassKey: passKeyBytes,
	}, nil
}
