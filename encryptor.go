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
	"sync"

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
	// mu protects passKey, writeKeyToFile, and keyFilePath
	mu sync.RWMutex

	// passKey is the encryption key (must be 32 bytes for AES-256)
	passKey []byte

	// writeKeyToFile determines whether to persist the key to disk
	writeKeyToFile bool

	// keyFilePath is the path where the key file will be stored
	keyFilePath string
}

// NewService creates a new encryption service with default settings
func NewService() *Service {
	return &Service{
		writeKeyToFile: false,
		keyFilePath:    DefaultPassKeyFileName,
	}
}

// SetWriteKeyToFile sets whether to write the key to file (thread-safe)
func (s *Service) SetWriteKeyToFile(write bool) {
	s.mu.Lock()
	s.writeKeyToFile = write
	s.mu.Unlock()
}

// GetWriteKeyToFile returns whether keys are written to file (thread-safe)
func (s *Service) GetWriteKeyToFile() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeKeyToFile
}

// SetKeyFilePath sets the key file path (thread-safe)
func (s *Service) SetKeyFilePath(path string) {
	s.mu.Lock()
	s.keyFilePath = path
	s.mu.Unlock()
}

// GetKeyFilePath returns the key file path (thread-safe)
func (s *Service) GetKeyFilePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyFilePath
}

// SetPassKey sets and validates the encryption passkey
func (s *Service) SetPassKey(passKey []byte) error {
	if len(passKey) == 0 {
		return ErrEmptyPassKey
	}

	if len(passKey) > KeyByteLength {
		return ErrPassKeyTooLong
	}

	// Derive key without holding lock (expensive cryptographic operation)
	derivedKey := s.deriveKey(passKey)

	s.mu.Lock()
	s.passKey = derivedKey
	s.mu.Unlock()

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

	// Derive key without holding lock (expensive cryptographic operation)
	derivedKey := pbkdf2.Key([]byte(password), salt, PBKDF2Iterations, KeyByteLength, sha256.New)

	s.mu.Lock()
	s.passKey = derivedKey
	s.mu.Unlock()

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

	s.mu.RLock()
	needsKey := len(s.passKey) == 0
	s.mu.RUnlock()

	if needsKey {
		if err := s.GeneratePassKey(); err != nil {
			return nil, fmt.Errorf("failed to generate passkey: %w", err)
		}
	}

	s.mu.RLock()
	keyCopy := make([]byte, len(s.passKey))
	copy(keyCopy, s.passKey)
	s.mu.RUnlock()

	aesCipher, err := aes.NewCipher(keyCopy)
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

	s.mu.RLock()
	if len(s.passKey) == 0 {
		s.mu.RUnlock()
		return nil, ErrPassKeyNotSet
	}
	keyCopy := make([]byte, len(s.passKey))
	copy(keyCopy, s.passKey)
	s.mu.RUnlock()

	block, err := aes.NewCipher(keyCopy)
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

	// Create a copy for file writing to avoid race with ClearPassKey
	var passKeyCopy []byte = nil

	s.mu.Lock()
	s.passKey = passKey
	writeToFile := s.writeKeyToFile
	keyFilePath := s.keyFilePath
	if keyFilePath == "" {
		keyFilePath = DefaultPassKeyFileName
	}

	// Only do this if we will be writing to file
	if writeToFile {
		passKeyCopy = make([]byte, len(passKey))
		copy(passKeyCopy, passKey)
	}
	s.mu.Unlock()

	if writeToFile {
		if err := s.writePassKeyToFile(passKeyCopy, keyFilePath); err != nil {
			return fmt.Errorf("failed to write key to file: %w", err)
		}
	}

	return nil
}

// writePassKeyToFile writes the passkey to a file with secure permissions
func (s *Service) writePassKeyToFile(passKey []byte, filePath string) error {
	encodedKey := hex.EncodeToString(passKey)

	if err := os.WriteFile(filePath, []byte(encodedKey), FilePermissions); err != nil {
		return fmt.Errorf("failed to write passkey file: %w", err)
	}

	return nil
}

// GetEncryptionServiceFromFile creates a Service from a passkey file
func (s *Service) GetEncryptionServiceFromFile(filePath string) (*Service, error) {
	s.mu.RLock()
	path := s.keyFilePath
	s.mu.RUnlock()

	if filePath != "" {
		path = filePath
	}

	if path == "" {
		path = DefaultPassKeyFileName
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
		keyFilePath: path,
	}, nil
}

// LoadEncryptionServiceFromFile is a convenience function to load from file
func LoadEncryptionServiceFromFile(filePath string) (*Service, error) {
	s := NewService()
	return s.GetEncryptionServiceFromFile(filePath)
}

// ExportPassKey returns a copy of the passkey (use with extreme caution)
func (s *Service) ExportPassKey() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

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
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.passKey {
		s.passKey[i] = 0
	}
	s.passKey = nil
}
