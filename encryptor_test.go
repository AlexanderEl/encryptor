package encryptor

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestNewService verifies default service initialization
func TestNewService(t *testing.T) {
	s := NewService()

	if s == nil {
		t.Fatal("NewService returned nil")
	}

	if s.WriteKeyToFile {
		t.Error("WriteKeyToFile should default to false")
	}

	if s.KeyFilePath != DefaultPassKeyFileName {
		t.Errorf("KeyFilePath = %s, want %s", s.KeyFilePath, DefaultPassKeyFileName)
	}
}

// TestEncryptDecrypt tests basic encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	original := []byte("super secret message that needs to be encrypted for safe keeping")

	encrypted, err := s.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(encrypted, original) {
		t.Error("Encrypted data should differ from original")
	}

	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("Decrypted = %s, want %s", decrypted, original)
	}
}

// TestEncryptDecryptWithGeneratedKey tests auto-generation of keys
func TestEncryptDecryptWithGeneratedKey(t *testing.T) {
	s := NewService()

	original := []byte("test message")

	encrypted, err := s.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("Decrypted = %s, want %s", decrypted, original)
	}
}

// TestSetPassKey tests passkey validation
func TestSetPassKey(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr error
	}{
		{
			name:    "valid short key",
			key:     []byte("test"),
			wantErr: nil,
		},
		{
			name:    "valid 32-byte key",
			key:     bytes.Repeat([]byte("a"), 32),
			wantErr: nil,
		},
		{
			name:    "empty key",
			key:     []byte{},
			wantErr: ErrEmptyPassKey,
		},
		{
			name:    "nil key",
			key:     nil,
			wantErr: ErrEmptyPassKey,
		},
		{
			name:    "too long key",
			key:     bytes.Repeat([]byte("a"), 33),
			wantErr: ErrPassKeyTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewService()
			err := s.SetPassKey(tt.key)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("SetPassKey() error = nil, wantErr %v", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("SetPassKey() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("SetPassKey() unexpected error = %v", err)
			}
		})
	}
}

// TestSetPassKeyFromPassword tests password-based key derivation
func TestSetPassKeyFromPassword(t *testing.T) {
	s := NewService()

	password := "my-secure-password"
	salt := make([]byte, SaltLength)

	if err := s.SetPassKeyFromPassword(password, salt); err != nil {
		t.Fatalf("SetPassKeyFromPassword failed: %v", err)
	}

	if len(s.passKey) != KeyByteLength {
		t.Errorf("passKey length = %d, want %d", len(s.passKey), KeyByteLength)
	}

	// Test with auto-generated salt
	s2 := NewService()
	if err := s2.SetPassKeyFromPassword(password, nil); err != nil {
		t.Fatalf("SetPassKeyFromPassword with auto-salt failed: %v", err)
	}

	// Test empty password
	s3 := NewService()
	if err := s3.SetPassKeyFromPassword("", nil); err == nil {
		t.Error("SetPassKeyFromPassword with empty password should fail")
	}
}

// TestEncryptEmptyData tests encryption of empty data
func TestEncryptEmptyData(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	_, err := s.Encrypt([]byte{})
	if err != ErrEmptyData {
		t.Errorf("Encrypt(empty) error = %v, want %v", err, ErrEmptyData)
	}

	_, err = s.Encrypt(nil)
	if err != ErrEmptyData {
		t.Errorf("Encrypt(nil) error = %v, want %v", err, ErrEmptyData)
	}
}

// TestDecryptEmptyData tests decryption of empty data
func TestDecryptEmptyData(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	_, err := s.Decrypt([]byte{})
	if err != ErrEmptyData {
		t.Errorf("Decrypt(empty) error = %v, want %v", err, ErrEmptyData)
	}

	_, err = s.Decrypt(nil)
	if err != ErrEmptyData {
		t.Errorf("Decrypt(nil) error = %v, want %v", err, ErrEmptyData)
	}
}

// TestDecryptWithoutKey tests decryption without setting a key
func TestDecryptWithoutKey(t *testing.T) {
	s := NewService()

	_, err := s.Decrypt([]byte("some data"))
	if err != ErrPassKeyNotSet {
		t.Errorf("Decrypt without key error = %v, want %v", err, ErrPassKeyNotSet)
	}
}

// TestDecryptInvalidCiphertext tests decryption of invalid ciphertext
func TestDecryptInvalidCiphertext(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	// Too short ciphertext (less than nonce size)
	_, err := s.Decrypt([]byte("short"))
	if err != ErrInvalidCiphertext {
		t.Errorf("Decrypt(short) error = %v, want %v", err, ErrInvalidCiphertext)
	}
}

// TestDecryptWithWrongKey tests decryption with incorrect key
func TestDecryptWithWrongKey(t *testing.T) {
	s1 := NewService()
	if err := s1.SetPassKey([]byte("key1")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	encrypted, err := s1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	s2 := NewService()
	if err := s2.SetPassKey([]byte("key2")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	_, err = s2.Decrypt(encrypted)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
}

// TestDecryptCorruptedData tests decryption of corrupted ciphertext
func TestDecryptCorruptedData(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	encrypted, err := s.Encrypt([]byte("secret message"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Corrupt the ciphertext
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[len(corrupted)-1] ^= 0xFF

	_, err = s.Decrypt(corrupted)
	if err == nil {
		t.Error("Decrypt with corrupted data should fail")
	}
}

// TestGeneratePassKey tests passkey generation
func TestGeneratePassKey(t *testing.T) {
	s := NewService()

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	if len(s.passKey) != KeyByteLength {
		t.Errorf("passKey length = %d, want %d", len(s.passKey), KeyByteLength)
	}

	// Generate another key and verify they're different
	oldKey := make([]byte, len(s.passKey))
	copy(oldKey, s.passKey)

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	if bytes.Equal(oldKey, s.passKey) {
		t.Error("Generated keys should be different")
	}
}

// TestGeneratePassKeyToFile tests key generation with file persistence
func TestGeneratePassKeyToFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "test_key.txt")

	s := NewService()
	s.WriteKeyToFile = true
	s.KeyFilePath = keyFile

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify file permissions
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Mode().Perm() != FilePermissions {
		t.Errorf("File permissions = %o, want %o", info.Mode().Perm(), FilePermissions)
	}

	// Verify file content
	data, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	decoded, err := hex.DecodeString(string(data))
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if !bytes.Equal(decoded, s.passKey) {
		t.Error("File content doesn't match passKey")
	}
}

// TestGetEncryptionServiceFromFile tests loading service from file
func TestGetEncryptionServiceFromFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "passkey.txt")

	// Create original service
	s1 := NewService()
	s1.WriteKeyToFile = true
	s1.KeyFilePath = keyFile

	original := []byte("test message")
	encrypted, err := s1.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Load service from file
	s2 := NewService()
	s2.KeyFilePath = keyFile
	loaded, err := s2.GetEncryptionServiceFromFile("")
	if err != nil {
		t.Fatalf("GetEncryptionServiceFromFile failed: %v", err)
	}

	// Verify keys match
	if !bytes.Equal(s1.passKey, loaded.passKey) {
		t.Error("Loaded key doesn't match original")
	}

	// Verify decryption works
	decrypted, err := loaded.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("Decrypted = %s, want %s", decrypted, original)
	}
}

// TestLoadEncryptionServiceFromFile tests convenience function
func TestLoadEncryptionServiceFromFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "key.txt")

	// Create a key file
	s1 := NewService()
	s1.WriteKeyToFile = true
	s1.KeyFilePath = keyFile
	if err := s1.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	// Load using convenience function
	s2, err := LoadEncryptionServiceFromFile(keyFile)
	if err != nil {
		t.Fatalf("LoadEncryptionServiceFromFile failed: %v", err)
	}

	if !bytes.Equal(s1.passKey, s2.passKey) {
		t.Error("Loaded key doesn't match original")
	}
}

// TestGetEncryptionServiceFromFileNotFound tests error handling for missing file
func TestGetEncryptionServiceFromFileNotFound(t *testing.T) {
	s := NewService()
	_, err := s.GetEncryptionServiceFromFile("/nonexistent/file.txt")

	if err == nil {
		t.Error("GetEncryptionServiceFromFile with nonexistent file should fail")
	}
}

// TestGetEncryptionServiceFromFileInvalidHex tests error handling for invalid hex
func TestGetEncryptionServiceFromFileInvalidHex(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "invalid.txt")

	// Write invalid hex
	if err := os.WriteFile(keyFile, []byte("not-valid-hex-data!"), FilePermissions); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s := NewService()
	_, err := s.GetEncryptionServiceFromFile(keyFile)

	if err == nil {
		t.Error("GetEncryptionServiceFromFile with invalid hex should fail")
	}
}

// TestGetEncryptionServiceFromFileWrongLength tests error handling for wrong key length
func TestGetEncryptionServiceFromFileWrongLength(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "short.txt")

	// Write short key (16 bytes instead of 32)
	shortKey := make([]byte, 16)
	rand.Read(shortKey)
	encodedKey := hex.EncodeToString(shortKey)

	if err := os.WriteFile(keyFile, []byte(encodedKey), FilePermissions); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s := NewService()
	_, err := s.GetEncryptionServiceFromFile(keyFile)

	if err == nil {
		t.Error("GetEncryptionServiceFromFile with wrong length should fail")
	}
}

// TestExportPassKey tests exporting the passkey
func TestExportPassKey(t *testing.T) {
	s := NewService()

	// Test without key set
	_, err := s.ExportPassKey()
	if err != ErrPassKeyNotSet {
		t.Errorf("ExportPassKey without key error = %v, want %v", err, ErrPassKeyNotSet)
	}

	// Test with key set
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	exported, err := s.ExportPassKey()
	if err != nil {
		t.Fatalf("ExportPassKey failed: %v", err)
	}

	if len(exported) != KeyByteLength {
		t.Errorf("Exported key length = %d, want %d", len(exported), KeyByteLength)
	}

	// Verify it's a copy (modifying export shouldn't affect original)
	exported[0] ^= 0xFF
	newExport, _ := s.ExportPassKey()
	if bytes.Equal(exported, newExport) {
		t.Error("ExportPassKey should return a copy, not the original")
	}
}

// TestClearPassKey tests securely clearing the passkey
func TestClearPassKey(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	originalPassKey, err := s.ExportPassKey()
	if err != nil {
		t.Errorf("failed to export pass key: %v", err)
	}

	s.ClearPassKey()

	if s.passKey != nil {
		t.Error("passKey should be nil after Clear")
	}

	// Verify operations fail after clearing
	_, err = s.Encrypt([]byte("test"))
	if err != nil {
		t.Error("failed to encrypt with missing passkey")
	}
	if bytes.Equal(originalPassKey, s.passKey) {
		t.Errorf("failed to clear passkey")
	}
}

// TestConcurrentEncryption tests concurrent encryption operations
func TestConcurrentEncryption(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	const numGoroutines = 1000
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			data := []byte("message " + string(rune(id)))
			encrypted, err := s.Encrypt(data)
			if err != nil {
				errors <- err
				return
			}

			decrypted, err := s.Decrypt(encrypted)
			if err != nil {
				errors <- err
				return
			}

			if !bytes.Equal(decrypted, data) {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

// TestLargeDataEncryption tests encryption of large data
func TestLargeDataEncryption(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	// Test with 10MB of data
	largeData := make([]byte, 10*1024*1024)
	rand.Read(largeData)

	encrypted, err := s.Encrypt(largeData)
	if err != nil {
		t.Fatalf("Encrypt large data failed: %v", err)
	}

	decrypted, err := s.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt large data failed: %v", err)
	}

	if !bytes.Equal(decrypted, largeData) {
		t.Error("Decrypted large data doesn't match original")
	}
}

// TestUniqueNonces verifies that each encryption generates a unique nonce
func TestUniqueNonces(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	data := []byte("test message")
	nonces := make(map[string]bool)

	for range 1000 {
		encrypted, err := s.Encrypt(data)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		// Extract nonce (first 12 bytes for GCM)
		nonce := hex.EncodeToString(encrypted[:12])

		if nonces[nonce] {
			t.Error("Duplicate nonce detected")
		}
		nonces[nonce] = true
	}
}

// BenchmarkEncrypt benchmarks encryption performance
func BenchmarkEncrypt(b *testing.B) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		b.Fatalf("SetPassKey failed: %v", err)
	}

	data := []byte("benchmark message for encryption testing")

	for b.Loop() {
		_, err := s.Encrypt(data)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

// BenchmarkDecrypt benchmarks decryption performance
func BenchmarkDecrypt(b *testing.B) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
		b.Fatalf("SetPassKey failed: %v", err)
	}

	data := []byte("benchmark message for decryption testing")
	encrypted, err := s.Encrypt(data)
	if err != nil {
		b.Fatalf("Encrypt failed: %v", err)
	}

	for b.Loop() {
		_, err := s.Decrypt(encrypted)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}

// BenchmarkGeneratePassKey benchmarks key generation
func BenchmarkGeneratePassKey(b *testing.B) {
	s := NewService()

	for b.Loop() {
		if err := s.GeneratePassKey(); err != nil {
			b.Fatalf("GeneratePassKey failed: %v", err)
		}
	}
}

// BenchmarkSetPassKeyFromPassword benchmarks password-based key derivation
func BenchmarkSetPassKeyFromPassword(b *testing.B) {
	s := NewService()
	password := "test-password"
	salt := make([]byte, SaltLength)

	for b.Loop() {
		if err := s.SetPassKeyFromPassword(password, salt); err != nil {
			b.Fatalf("SetPassKeyFromPassword failed: %v", err)
		}
	}
}
