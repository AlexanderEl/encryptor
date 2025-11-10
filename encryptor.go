package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// KeyByteLength is the required length for AES-256 encryption keys
	KeyByteLength = 32

	// DefaultPassKeyFileName is the default filename for storing encryption keys
	DefaultPassKeyFileName = "passkey.txt"

	// FilePermissions sets restrictive permissions (owner read/write only)
	FilePermissions = 0600

	// PBKDF2Iterations is the number of iterations for key derivation
	PBKDF2Iterations = 100000

	// SaltLength is the length of the salt used in key derivation
	SaltLength = 16
)

var (
	// ErrEmptyPassKey is returned when an empty passkey is provided
	ErrEmptyPassKey = errors.New("passkey cannot be empty")

	// ErrPassKeyTooLong is returned when passkey exceeds maximum length
	ErrPassKeyTooLong = errors.New("passkey exceeds maximum length of 32 bytes")

	// ErrEmptyData is returned when trying to encrypt/decrypt empty data
	ErrEmptyData = errors.New("data cannot be empty")

	// ErrInvalidCiphertext is returned when ciphertext is too short
	ErrInvalidCiphertext = errors.New("ciphertext too short")

	// ErrPassKeyNotSet is returned when operations require a passkey that hasn't been set
	ErrPassKeyNotSet = errors.New("passkey not set")
)

// Encryptor defines the interface for encryption operations
type Encryptor interface {
	// SetPassKey sets the passkey and validates it
	SetPassKey(key []byte) error

	// SetPassKeyFromPassword derives a secure key from a password
	SetPassKeyFromPassword(password string, salt []byte) error

	// Encrypt encrypts data using AES-256-GCM
	Encrypt(data []byte) ([]byte, error)

	// Decrypt decrypts data using AES-256-GCM
	Decrypt(data []byte) ([]byte, error)

	// GeneratePassKey generates a cryptographically secure random passkey
	GeneratePassKey() error

	// ExportPassKey returns the passkey (use with caution)
	ExportPassKey() ([]byte, error)
}

// Service implements the Encryptor interface
type Service struct {
	// passKey is the encryption key (must be 32 bytes for AES-256)
	passKey []byte

	// WriteKeyToFile determines whether to persist the key to disk
	WriteKeyToFile bool

	// KeyFilePath is the path where the key file will be stored
	KeyFilePath string
}

// NewService creates a new encryption service with default settings
func NewService() *Service {
	return &Service{
		WriteKeyToFile: false,
		KeyFilePath:    DefaultPassKeyFileName,
	}
}

// SetPassKey sets and validates the encryption passkey
func (s *Service) SetPassKey(passKey []byte) error {
	if len(passKey) == 0 {
		return ErrEmptyPassKey
	}

	if len(passKey) > KeyByteLength {
		return ErrPassKeyTooLong
	}

	// Pad the key to required length using PBKDF2 for cryptographic security
	s.passKey = s.deriveKey(passKey)
	return nil
}

// SetPassKeyFromPassword derives a secure key from a user password using PBKDF2
func (s *Service) SetPassKeyFromPassword(password string, salt []byte) error {
	if password == "" {
		return ErrEmptyPassKey
	}

	if salt == nil {
		salt = make([]byte, SaltLength)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	s.passKey = pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, KeyByteLength, sha256.New)
	return nil
}

// Derives a key of proper length using PBKDF2
func (s *Service) deriveKey(key []byte) []byte {
	// Use a deterministic salt derived from the key for backwards compatibility
	hash := sha256.Sum256(key)
	salt := hash[:SaltLength]
	return pbkdf2.Key(key, salt, PBKDF2Iterations, KeyByteLength, sha256.New)
}

// Encrypt encrypts data using AES-256-GCM
func (s *Service) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	// Auto-generate passkey if not set
	if len(s.passKey) == 0 {
		if err := s.GeneratePassKey(); err != nil {
			return nil, fmt.Errorf("failed to generate passkey: %w", err)
		}
	}

	aesCipher, err := aes.NewCipher(s.passKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts data using AES-256-GCM
func (s *Service) Decrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrEmptyData
	}

	if len(s.passKey) == 0 {
		return nil, ErrPassKeyNotSet
	}

	block, err := aes.NewCipher(s.passKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidCiphertext
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GeneratePassKey generates a cryptographically secure random passkey
func (s *Service) GeneratePassKey() error {
	passKey := make([]byte, KeyByteLength)
	if _, err := io.ReadFull(rand.Reader, passKey); err != nil {
		return fmt.Errorf("failed to generate random passkey: %w", err)
	}

	s.passKey = passKey

	if s.WriteKeyToFile {
		if err := s.writeKeyToFile(); err != nil {
			return fmt.Errorf("failed to write key to file: %w", err)
		}
	}

	return nil
}

// writeKeyToFile writes the passkey to a file with secure permissions
func (s *Service) writeKeyToFile() error {
	encodedKey := hex.EncodeToString(s.passKey)

	if err := os.WriteFile(s.KeyFilePath, []byte(encodedKey), FilePermissions); err != nil {
		return fmt.Errorf("failed to write passkey file: %w", err)
	}

	return nil
}

// GetEncryptionServiceFromFile creates a Service from a passkey file
func (s *Service) GetEncryptionServiceFromFile(filePath string) (*Service, error) {
	path := s.KeyFilePath
	if filePath != "" {
		path = filePath
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("passkey file does not exist: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read passkey file: %w", err)
	}

	passKeyBytes, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode passkey: %w", err)
	}

	if len(passKeyBytes) != KeyByteLength {
		return nil, fmt.Errorf("invalid passkey length: expected %d, got %d", KeyByteLength, len(passKeyBytes))
	}

	return &Service{
		passKey:     passKeyBytes,
		KeyFilePath: path,
	}, nil
}

// LoadEncryptionServiceFromFile is a convenience function to load from file
func LoadEncryptionServiceFromFile(filePath string) (*Service, error) {
	s := NewService()
	return s.GetEncryptionServiceFromFile(filePath)
}

// ExportPassKey returns a copy of the passkey (use with extreme caution)
func (s *Service) ExportPassKey() ([]byte, error) {
	if len(s.passKey) == 0 {
		return nil, ErrPassKeyNotSet
	}

	// Return a copy to prevent external modification
	keyCopy := make([]byte, len(s.passKey))
	copy(keyCopy, s.passKey)
	return keyCopy, nil
}

// ClearPassKey securely clears the passkey from memory
func (s *Service) ClearPassKey() {
	for i := range s.passKey {
		s.passKey[i] = 0
	}
	s.passKey = nil
}
