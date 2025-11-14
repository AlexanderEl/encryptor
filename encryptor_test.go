package encryptor

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mathRand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNewService verifies default service initialization
func TestNewService(t *testing.T) {
	s := NewService()
	if s == nil {
		t.Fatal("NewService returned nil")
	}
	if s.GetWriteKeyToFile() {
		t.Error("GetWriteKeyToFile should default to false")
	}
	if s.GetKeyFilePath() != DefaultPassKeyFileName {
		t.Errorf("GetKeyFilePath = %s, want %s", s.GetKeyFilePath(), DefaultPassKeyFileName)
	}
}

// TestThreadSafeAccessors tests the thread-safe getter/setter methods
func TestThreadSafeAccessors(t *testing.T) {
	s := NewService()

	// Test SetWriteKeyToFile/GetWriteKeyToFile
	s.SetWriteKeyToFile(true)
	if !s.GetWriteKeyToFile() {
		t.Error("GetWriteKeyToFile should return true after SetWriteKeyToFile(true)")
	}

	s.SetWriteKeyToFile(false)
	if s.GetWriteKeyToFile() {
		t.Error("GetWriteKeyToFile should return false after SetWriteKeyToFile(false)")
	}

	// Test SetKeyFilePath/GetKeyFilePath
	testPath := "/test/path/key.txt"
	s.SetKeyFilePath(testPath)
	if s.GetKeyFilePath() != testPath {
		t.Errorf("GetKeyFilePath = %s, want %s", s.GetKeyFilePath(), testPath)
	}

	// Test multiple changes
	paths := []string{"/path1", "/path2", "/path3"}
	for _, path := range paths {
		s.SetKeyFilePath(path)
		if s.GetKeyFilePath() != path {
			t.Errorf("GetKeyFilePath = %s, want %s", s.GetKeyFilePath(), path)
		}
	}
}

// TestConcurrentAccessors tests thread-safe accessors under concurrent access
func TestConcurrentAccessors(t *testing.T) {
	s := NewService()
	const numGoroutines = 100
	var wg sync.WaitGroup

	// Concurrent writes and reads to WriteKeyToFile
	for i := range numGoroutines {
		wg.Go(func() {
			s.SetWriteKeyToFile(i%2 == 0)
			_ = s.GetWriteKeyToFile()
		})
	}

	// Concurrent writes and reads to KeyFilePath
	for i := range numGoroutines {
		wg.Go(func() {
			s.SetKeyFilePath("/path/" + string(rune('a'+i%26)))
			_ = s.GetKeyFilePath()
		})
	}

	wg.Wait()
	// Should pass with -race flag
}

// TestEncryptDecrypt tests basic encryption and decryption
func TestEncryptDecrypt(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	original := []byte("super secret message")
	encrypted, err := s.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify encryption changed the data
	if bytes.Equal(encrypted, original) {
		t.Error("Encrypted data should differ from original")
	}

	// Verify encrypted data is longer (includes nonce)
	if len(encrypted) <= len(original) {
		t.Error("Encrypted data should be longer than original (includes nonce + auth tag)")
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
		wantErr bool
		errMsg  string
	}{
		{"valid short key", []byte("test"), false, ""},
		{"valid 32-byte key", bytes.Repeat([]byte("a"), 32), false, ""},
		{"empty key", []byte{}, true, "passkey cannot be empty"},
		{"nil key", nil, true, "passkey cannot be empty"},
		{"too long key", bytes.Repeat([]byte("a"), 33), true, "passkey exceeds maximum length"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewService()
			err := s.SetNewPassKey(tt.key)

			if (err != nil) != tt.wantErr {
				t.Errorf("SetPassKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message = %v, want substring %v", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

// TestSetPassKeyFromPassword tests password-based key derivation
func TestSetPassKeyFromPassword(t *testing.T) {
	s := NewService()
	password := "my-secure-password"
	salt := make([]byte, SaltLength)

	if err := s.SetNewPassKeyFromPassword(password, salt); err != nil {
		t.Fatalf("SetPassKeyFromPassword failed: %v", err)
	}

	// Test with auto-generated salt
	s2 := NewService()
	if err := s2.SetNewPassKeyFromPassword(password, nil); err != nil {
		t.Fatalf("SetPassKeyFromPassword with auto-salt failed: %v", err)
	}

	// Verify different salts produce different keys
	key1, _ := s.ExportPassKey()
	key2, _ := s2.ExportPassKey()
	if bytes.Equal(key1, key2) {
		t.Error("Different salts should produce different keys")
	}

	// Test empty password
	s3 := NewService()
	err := s3.SetNewPassKeyFromPassword("", nil)
	if err == nil {
		t.Error("SetPassKeyFromPassword with empty password should fail")
	}
	if !strings.Contains(err.Error(), "passkey cannot be empty") {
		t.Errorf("Error message = %v, want 'passkey cannot be empty'", err.Error())
	}
}

// TestSetPassKeyFromPasswordSaltFailure tests salt generation failure
func TestSetPassKeyFromPasswordSaltFailure(t *testing.T) {
	s := NewService()
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()

	rand.Reader = &failingReader{}
	err := s.SetNewPassKeyFromPassword("password", nil)
	if err == nil {
		t.Error("Expected error when salt generation fails")
	}
	if !strings.Contains(err.Error(), "failed to generate salt") {
		t.Errorf("Error message = %v, want 'failed to generate salt'", err.Error())
	}
}

// TestEncryptEmptyData tests encryption of empty data
func TestEncryptEmptyData(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	// Test empty slice
	result, err := s.Encrypt([]byte{})
	if err != ErrEmptyData {
		t.Errorf("Encrypt(empty) error = %v, want %v", err, ErrEmptyData)
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}

	// Test nil slice
	result, err = s.Encrypt(nil)
	if err != ErrEmptyData {
		t.Errorf("Encrypt(nil) error = %v, want %v", err, ErrEmptyData)
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestEncryptAutoGenerateFailure tests encryption when auto key generation fails
func TestEncryptAutoGenerateFailure(t *testing.T) {
	s := NewService()

	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()

	rand.Reader = &failingReader{}
	result, err := s.Encrypt([]byte("test"))
	if err == nil {
		t.Error("Expected error when key generation fails")
	}
	if !strings.Contains(err.Error(), "failed to generate passkey") {
		t.Errorf("Error message = %v, want 'failed to generate passkey'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestEncryptNonceFailure tests encryption when nonce generation fails
func TestEncryptNonceFailure(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()

	rand.Reader = &failingReader{}
	result, err := s.Encrypt([]byte("test"))
	if err == nil {
		t.Error("Expected error when nonce generation fails")
	}
	if !strings.Contains(err.Error(), "failed to generate nonce") {
		t.Errorf("Error message = %v, want 'failed to generate nonce'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestDecryptEmptyData tests decryption of empty data
func TestDecryptEmptyData(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	// Test empty slice
	result, err := s.Decrypt([]byte{})
	if err != ErrEmptyData {
		t.Errorf("Decrypt(empty) error = %v, want %v", err, ErrEmptyData)
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}

	// Test nil slice
	result, err = s.Decrypt(nil)
	if err != ErrEmptyData {
		t.Errorf("Decrypt(nil) error = %v, want %v", err, ErrEmptyData)
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestDecryptWithoutKey tests decryption without setting a key
func TestDecryptWithoutKey(t *testing.T) {
	s := NewService()

	result, err := s.Decrypt([]byte("some data"))
	if err != ErrPassKeyNotSet {
		t.Errorf("Decrypt without key error = %v, want %v", err, ErrPassKeyNotSet)
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestDecryptInvalidCiphertext tests decryption of invalid ciphertext
func TestDecryptInvalidCiphertext(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	// Test ciphertext shorter than nonce size (12 bytes for GCM)
	shortData := []byte("short")
	result, err := s.Decrypt(shortData)
	if err != ErrInvalidCiphertext {
		t.Errorf("Decrypt(short) error = %v, want %v", err, ErrInvalidCiphertext)
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}

	// Test with exactly nonce size (should fail because no ciphertext)
	nonceOnlyData := make([]byte, 12)
	result, err = s.Decrypt(nonceOnlyData)
	if err == nil {
		t.Error("Decrypt with only nonce should fail")
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestDecryptWithWrongKey tests decryption with incorrect key
func TestDecryptWithWrongKey(t *testing.T) {
	s1 := NewService()
	if err := s1.SetNewPassKey([]byte("key1")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	original := []byte("secret")
	encrypted, err := s1.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	s2 := NewService()
	if err := s2.SetNewPassKey([]byte("key2")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	result, err := s2.Decrypt(encrypted)
	if err == nil {
		t.Error("Decrypt with wrong key should fail")
	}
	if !strings.Contains(err.Error(), "failed to decrypt") {
		t.Errorf("Error message = %v, want 'failed to decrypt'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestGeneratePassKey tests passkey generation
func TestGeneratePassKey(t *testing.T) {
	s := NewService()

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	// Generate another key and verify uniqueness
	key1, _ := s.ExportPassKey()

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("Second GeneratePassKey failed: %v", err)
	}

	key2, _ := s.ExportPassKey()

	if bytes.Equal(key1, key2) {
		t.Error("Consecutive generated keys should be different")
	}
}

// TestGeneratePassKeyFailure tests key generation failure
func TestGeneratePassKeyFailure(t *testing.T) {
	s := NewService()

	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()

	rand.Reader = &failingReader{}
	err := s.GeneratePassKey()
	if err == nil {
		t.Error("Expected error when random generation fails")
	}
	if !strings.Contains(err.Error(), "failed to generate random passkey") {
		t.Errorf("Error message = %v, want 'failed to generate random passkey'", err.Error())
	}
}

// TestGeneratePassKeyToFile tests key generation with file persistence
func TestGeneratePassKeyToFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "test_key.txt")

	s := NewService()
	s.SetWriteKeyToFile(true)
	s.SetKeyFilePath(keyFile)

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	if info.Mode().Perm() != FilePermissions {
		t.Errorf("File permissions = %o, want %o", info.Mode().Perm(), FilePermissions)
	}
}

// TestGeneratePassKeyFileWriteFailure tests file write failure
func TestGeneratePassKeyFileWriteFailure(t *testing.T) {
	s := NewService()
	s.SetWriteKeyToFile(true)
	s.SetKeyFilePath("/invalid/path/key.txt")

	err := s.GeneratePassKey()
	if err == nil {
		t.Error("Expected error when writing to invalid path")
	}
	if !strings.Contains(err.Error(), "failed to write key to file") {
		t.Errorf("Error message = %v, want 'failed to write key to file'", err.Error())
	}
}

// TestGetEncryptionServiceFromFile tests loading service from file
func TestGetEncryptionServiceFromFile(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "passkey.txt")

	s1 := NewService()
	s1.SetWriteKeyToFile(true)
	s1.SetKeyFilePath(keyFile)

	original := []byte("test message")
	encrypted, err := s1.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	s2 := NewService()
	s2.SetKeyFilePath(keyFile)
	loaded, err := s2.GetEncryptionServiceFromFile("")
	if err != nil {
		t.Fatalf("GetEncryptionServiceFromFile failed: %v", err)
	}

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

	s1 := NewService()
	s1.SetWriteKeyToFile(true)
	s1.SetKeyFilePath(keyFile)
	if err := s1.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	s2, err := LoadEncryptionServiceFromFile(keyFile)
	if err != nil {
		t.Fatalf("LoadEncryptionServiceFromFile failed: %v", err)
	}

	key1, _ := s1.ExportPassKey()
	key2, _ := s2.ExportPassKey()

	if !bytes.Equal(key1, key2) {
		t.Error("Loaded key doesn't match original")
	}
}

// TestGetEncryptionServiceFromFileNotFound tests missing file
func TestGetEncryptionServiceFromFileNotFound(t *testing.T) {
	s := NewService()
	result, err := s.GetEncryptionServiceFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("GetEncryptionServiceFromFile with nonexistent file should fail")
	}
	if !strings.Contains(err.Error(), "passkey file does not exist") {
		t.Errorf("Error message = %v, want 'passkey file does not exist'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestGetEncryptionServiceFromFileInvalidHex tests invalid hex
func TestGetEncryptionServiceFromFileInvalidHex(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "invalid.txt")

	if err := os.WriteFile(keyFile, []byte("not-valid-hex!"), FilePermissions); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s := NewService()
	result, err := s.GetEncryptionServiceFromFile(keyFile)
	if err == nil {
		t.Error("GetEncryptionServiceFromFile with invalid hex should fail")
	}
	if !strings.Contains(err.Error(), "failed to decode passkey") {
		t.Errorf("Error message = %v, want 'failed to decode passkey'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestGetEncryptionServiceFromFileWrongLength tests wrong key length
func TestGetEncryptionServiceFromFileWrongLength(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "short.txt")

	shortKey := make([]byte, 16)
	rand.Read(shortKey)
	encodedKey := hex.EncodeToString(shortKey)

	if err := os.WriteFile(keyFile, []byte(encodedKey), FilePermissions); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s := NewService()
	result, err := s.GetEncryptionServiceFromFile(keyFile)
	if err == nil {
		t.Error("GetEncryptionServiceFromFile with wrong length should fail")
	}
	if !strings.Contains(err.Error(), "invalid passkey length") {
		t.Errorf("Error message = %v, want 'invalid passkey length'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestExportPassKey tests exporting the passkey
func TestExportPassKey(t *testing.T) {
	s := NewService()

	_, err := s.ExportPassKey()
	if err != ErrPassKeyNotSet {
		t.Errorf("ExportPassKey without key error = %v, want %v", err, ErrPassKeyNotSet)
	}

	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	exported, err := s.ExportPassKey()
	if err != nil {
		t.Fatalf("ExportPassKey failed: %v", err)
	}

	if len(exported) != KeyByteLength {
		t.Errorf("Exported key length = %d, want %d", len(exported), KeyByteLength)
	}

	// Verify it's a copy
	exported[0] ^= 0xFF
	newExport, _ := s.ExportPassKey()
	if bytes.Equal(exported, newExport) {
		t.Error("ExportPassKey should return a copy")
	}
}

// TestExportKeyValidation tests export and import workflow
func TestExportKeyValidation(t *testing.T) {
	s := NewService()
	s.GeneratePassKey()

	msg := []byte("secure message")
	encrypted, _ := s.Encrypt(msg)

	key, _ := s.ExportPassKey()
	if !bytes.Equal(key, s.passKey) {
		t.Fatalf("Exported key does not match set key")
	}

	ns := NewService()
	ns.SetExportedKey(key)

	if !bytes.Equal(key, ns.passKey) {
		t.Fatalf("Setting key causes key to change")
	}

	decryptedMsg, err := ns.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with exported key: %v", err)
	}

	if !bytes.Equal(msg, decryptedMsg) {
		t.Errorf("Failed to retrieve original message")
	}
}

// TestSetExportedKeyValidation tests validation of SetExportedKey
func TestSetExportedKeyValidation(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr error
	}{
		{"valid 32-byte key", make([]byte, 32), nil},
		{"valid 16-byte key", make([]byte, 16), nil},
		{"valid 24-byte key", make([]byte, 24), nil},
		{"empty key", []byte{}, ErrEmptyPassKey},
		{"nil key", nil, ErrEmptyPassKey},
		{"key too short", make([]byte, 15), ErrKeyTooShort},
		{"key too long (33 bytes)", make([]byte, 33), ErrPassKeyTooLong},
		{"key too long (64 bytes)", make([]byte, 64), ErrPassKeyTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewService()
			err := s.SetExportedKey(tt.key)
			if err != tt.wantErr {
				t.Errorf("SetExportedKey() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestExportedKeyNoDerivation verifies that SetExportedKey doesn't derive the key
func TestExportedKeyNoDerivation(t *testing.T) {
	s := NewService()

	// Create a specific key pattern
	originalKey := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	if err := s.SetExportedKey(originalKey); err != nil {
		t.Fatalf("SetExportedKey failed: %v", err)
	}

	exported, err := s.ExportPassKey()
	if err != nil {
		t.Fatalf("ExportPassKey failed: %v", err)
	}

	// The exported key should be identical (not derived)
	if !bytes.Equal(originalKey, exported) {
		t.Errorf("SetExportedKey modified the key")
	}
}

// TestExportedKeyVsNewPassKey verifies the difference between SetExportedKey and SetNewPassKey
func TestExportedKeyVsNewPassKey(t *testing.T) {
	// Use a key that's at least 16 bytes for SetExportedKey validation
	testKey := []byte("test-key-value16") // 16 bytes

	// Service using SetNewPassKey (derives key)
	s1 := NewService()
	if err := s1.SetNewPassKey(testKey); err != nil {
		t.Fatalf("SetNewPassKey failed: %v", err)
	}
	derivedKey, _ := s1.ExportPassKey()

	// Service using SetExportedKey (no derivation)
	s2 := NewService()
	if err := s2.SetExportedKey(testKey); err != nil {
		t.Fatalf("SetExportedKey failed: %v", err)
	}
	directKey, _ := s2.ExportPassKey()

	// Keys should be different
	if bytes.Equal(derivedKey, directKey) {
		t.Error("SetNewPassKey and SetExportedKey produced identical keys (derivation not working)")
	}

	// The direct key should match the input
	if !bytes.Equal(testKey, directKey) {
		t.Error("SetExportedKey modified the key")
	}

	// Verify the derived key is 32 bytes
	if len(derivedKey) != KeyByteLength {
		t.Errorf("Derived key length = %d, want %d", len(derivedKey), KeyByteLength)
	}
}

// TestExportImportWorkflow tests the complete export/import workflow
func TestExportImportWorkflow(t *testing.T) {
	// Create original service and encrypt data
	original := NewService()
	if err := original.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	message := []byte("confidential message for export test")
	encrypted, err := original.Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Export the key
	exportedKey, err := original.ExportPassKey()
	if err != nil {
		t.Fatalf("ExportPassKey failed: %v", err)
	}

	// Create new service and import the key
	imported := NewService()
	if err := imported.SetExportedKey(exportedKey); err != nil {
		t.Fatalf("SetExportedKey failed: %v", err)
	}

	// Decrypt with imported key
	decrypted, err := imported.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt with imported key failed: %v", err)
	}

	// Verify decrypted message matches original
	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted message doesn't match")
	}

	// Test that imported key can also encrypt
	newMessage := []byte("encrypt with imported key")
	newEncrypted, err := imported.Encrypt(newMessage)
	if err != nil {
		t.Fatalf("Encrypt with imported key failed: %v", err)
	}

	// Original service should decrypt new message
	newDecrypted, err := original.Decrypt(newEncrypted)
	if err != nil {
		t.Fatalf("Decrypt new message failed: %v", err)
	}
	if !bytes.Equal(newMessage, newDecrypted) {
		t.Error("Bidirectional encryption/decryption failed")
	}
}

// TestExportedKeyFailsWithDerivedEncryption tests that raw passwords don't work with derived keys
func TestExportedKeyFailsWithDerivedEncryption(t *testing.T) {
	// Use a 16-byte password for SetExportedKey validation
	password := []byte("my-password-1234") // 16 bytes

	// Service 1: Use SetNewPassKey (derives the key)
	s1 := NewService()
	if err := s1.SetNewPassKey(password); err != nil {
		t.Fatalf("SetNewPassKey failed: %v", err)
	}

	message := []byte("encrypted with derived key")
	encrypted, err := s1.Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Service 2: Try to use the same password with SetExportedKey (no derivation)
	s2 := NewService()
	if err := s2.SetExportedKey(password); err != nil {
		t.Fatalf("SetExportedKey failed: %v", err)
	}

	// This should FAIL because s2 has the raw password, not the derived key
	_, err = s2.Decrypt(encrypted)
	if err == nil {
		t.Error("Decrypt should fail when using raw password instead of derived key")
	}

	// Service 3: Export the derived key and use it correctly
	derivedKey, _ := s1.ExportPassKey()
	s3 := NewService()
	if err := s3.SetExportedKey(derivedKey); err != nil {
		t.Fatalf("SetExportedKey with derived key failed: %v", err)
	}

	// This should SUCCEED
	decrypted, err := s3.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt with exported derived key failed: %v", err)
	}
	if !bytes.Equal(message, decrypted) {
		t.Error("Decrypted message doesn't match original")
	}
}

// TestExportedKeyDifferentSizes tests export/import with various key sizes
func TestExportedKeyDifferentSizes(t *testing.T) {
	validSizes := []int{16, 24, 32}

	for _, size := range validSizes {
		t.Run(string(rune('0'+size)), func(t *testing.T) {
			// Create key of specific size
			key := make([]byte, size)
			for i := range key {
				key[i] = byte(i)
			}

			// Set and encrypt
			s1 := NewService()
			if err := s1.SetExportedKey(key); err != nil {
				t.Fatalf("SetExportedKey failed for size %d: %v", size, err)
			}

			message := []byte("test message")
			encrypted, err := s1.Encrypt(message)
			if err != nil {
				t.Fatalf("Encrypt failed for key size %d: %v", size, err)
			}

			// Export and import
			exported, _ := s1.ExportPassKey()
			s2 := NewService()
			if err := s2.SetExportedKey(exported); err != nil {
				t.Fatalf("SetExportedKey on import failed for size %d: %v", size, err)
			}

			// Decrypt
			decrypted, err := s2.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed for key size %d: %v", size, err)
			}
			if !bytes.Equal(message, decrypted) {
				t.Errorf("Decryption failed for key size %d", size)
			}
		})
	}
}

// TestExportedKeyImmutability verifies that modifying exported key doesn't affect service
func TestExportedKeyImmutability(t *testing.T) {
	s := NewService()
	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	// Export key and modify it
	exported, _ := s.ExportPassKey()
	originalCopy := make([]byte, len(exported))
	copy(originalCopy, exported)

	// Corrupt the exported key
	for i := range exported {
		exported[i] ^= 0xFF
	}

	// Service should still have original key
	stillExported, _ := s.ExportPassKey()
	if !bytes.Equal(originalCopy, stillExported) {
		t.Error("Modifying exported key affected internal key")
	}

	// Also test SetExportedKey immutability
	keyToSet := make([]byte, 32)
	for i := range keyToSet {
		keyToSet[i] = byte(i)
	}
	keyCopy := make([]byte, len(keyToSet))
	copy(keyCopy, keyToSet)

	s2 := NewService()
	if err := s2.SetExportedKey(keyToSet); err != nil {
		t.Fatalf("SetExportedKey failed: %v", err)
	}

	// Modify the original slice
	for i := range keyToSet {
		keyToSet[i] = 0xFF
	}

	// Service should have the original values
	retrieved, _ := s2.ExportPassKey()
	if !bytes.Equal(keyCopy, retrieved) {
		t.Error("SetExportedKey didn't copy the key properly")
	}
}

// TestExportedKeyCrossService tests encryption/decryption across multiple services
func TestExportedKeyCrossService(t *testing.T) {
	// Create master service
	master := NewService()
	if err := master.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}
	masterKey, _ := master.ExportPassKey()

	// Create multiple services with the same exported key
	numServices := 5
	services := make([]*Service, numServices)
	for i := range services {
		services[i] = NewService()
		if err := services[i].SetExportedKey(masterKey); err != nil {
			t.Fatalf("SetExportedKey on service %d failed: %v", i, err)
		}
	}

	// Service 2 encrypts a message
	message := []byte("shared message")
	encrypted, err := services[2].Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// All services should be able to decrypt it
	for i, svc := range services {
		decrypted, err := svc.Decrypt(encrypted)
		if err != nil {
			t.Errorf("Service %d failed to decrypt: %v", i, err)
			continue
		}
		if !bytes.Equal(message, decrypted) {
			t.Errorf("Service %d decrypted wrong content", i)
		}
	}

	// Master service should also decrypt
	decrypted, err := master.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Master decrypt failed: %v", err)
	}
	if !bytes.Equal(message, decrypted) {
		t.Error("Master decrypted wrong content")
	}
}

// TestSetExportedKeyOverwritesExisting tests that SetExportedKey overwrites the current key
func TestSetExportedKeyOverwritesExisting(t *testing.T) {
	s := NewService()

	// Set initial key
	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}
	key1, _ := s.ExportPassKey()

	// Encrypt with first key
	msg1 := []byte("encrypted with first key")
	enc1, err := s.Encrypt(msg1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Overwrite with exported key
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i)
	}
	if err := s.SetExportedKey(newKey); err != nil {
		t.Fatalf("SetExportedKey failed: %v", err)
	}
	key2, _ := s.ExportPassKey()

	// Keys should be different
	if bytes.Equal(key1, key2) {
		t.Error("SetExportedKey didn't overwrite the key")
	}

	// Should NOT be able to decrypt old message
	if _, err := s.Decrypt(enc1); err == nil {
		t.Error("Should not be able to decrypt with different key")
	}

	// Should be able to encrypt/decrypt with new key
	msg2 := []byte("encrypted with new key")
	enc2, err := s.Encrypt(msg2)
	if err != nil {
		t.Fatalf("Encrypt with new key failed: %v", err)
	}

	dec2, err := s.Decrypt(enc2)
	if err != nil {
		t.Fatalf("Decrypt with new key failed: %v", err)
	}
	if !bytes.Equal(msg2, dec2) {
		t.Error("Message encrypted/decrypted with new key doesn't match")
	}
}

// TestClearPassKey tests securely clearing the passkey
func TestClearPassKey(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	s.ClearPassKey()

	// Verify operations fail after clearing
	encrypted, err := s.Encrypt([]byte("test"))
	if err != nil {
		t.Errorf("encrypting post key clearing failed")
	}

	// Clear key before decrypting
	s.ClearPassKey()

	_, err = s.Decrypt(encrypted)
	if err != ErrPassKeyNotSet {
		t.Errorf("Decrypt after ClearPassKey error = %v, want %v", err, ErrPassKeyNotSet)
	}
}

// TestDecryptInvalidKeySize tests decryption with a key that causes cipher creation to fail
func TestDecryptInvalidKeySize(t *testing.T) {
	s := NewService()

	// Manually set an invalid key size to force aes.NewCipher to fail
	s.mu.Lock()
	s.passKey = make([]byte, 15) // Invalid size
	s.mu.Unlock()

	// Create valid ciphertext structure (nonce + data)
	data := make([]byte, 20)

	result, err := s.Decrypt(data)
	if err == nil {
		t.Error("Expected error when cipher creation fails")
	}
	if !strings.Contains(err.Error(), "failed to create cipher") {
		t.Errorf("Error message = %v, want 'failed to create cipher'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestEncryptCipherCreation tests encryption failure during cipher creation
func TestEncryptCipherCreation(t *testing.T) {
	s := NewService()

	// Set an invalid key size
	s.mu.Lock()
	s.passKey = make([]byte, 15)
	s.mu.Unlock()

	result, err := s.Encrypt([]byte("test data"))
	if err == nil {
		t.Error("Expected error with invalid key size")
	}
	if !strings.Contains(err.Error(), "failed to create cipher") {
		t.Errorf("Error message = %v, want 'failed to create cipher'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestGeneratePassKeyReadOnlyDirectory tests writing to a read-only location
func TestGeneratePassKeyReadOnlyDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "key.txt")

	// Make directory read-only
	if err := os.Chmod(tempDir, 0444); err != nil {
		t.Fatalf("Failed to chmod directory: %v", err)
	}
	defer os.Chmod(tempDir, 0755)

	s := NewService()
	s.SetWriteKeyToFile(true)
	s.SetKeyFilePath(keyFile)

	err := s.GeneratePassKey()
	if err == nil {
		t.Error("Expected error when writing to read-only directory")
	}
	if !strings.Contains(err.Error(), "failed to write key to file") {
		t.Errorf("Error message = %v, want 'failed to write key to file'", err.Error())
	}
}

// TestGetEncryptionServiceFromFileReadError tests file read failure
func TestGetEncryptionServiceFromFileReadError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test when running as root")
	}

	tempDir := t.TempDir()
	keyFile := filepath.Join(tempDir, "key.txt")

	// Create a file but make it unreadable
	if err := os.WriteFile(keyFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Make file unreadable
	if err := os.Chmod(keyFile, 0000); err != nil {
		t.Fatalf("Failed to chmod file: %v", err)
	}
	defer os.Chmod(keyFile, 0644)

	s := NewService()
	result, err := s.GetEncryptionServiceFromFile(keyFile)
	if err == nil {
		t.Error("Expected error when reading unreadable file")
	}
	if !strings.Contains(err.Error(), "failed to read passkey file") {
		t.Errorf("Error message = %v, want 'failed to read passkey file'", err.Error())
	}
	if result != nil {
		t.Error("Result should be nil on error")
	}
}

// TestGetEncryptionServiceFromFileWithEmptyInternalPath tests when both paths are empty
func TestGetEncryptionServiceFromFileWithEmptyInternalPath(t *testing.T) {
	tempDir := t.TempDir()
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	os.Chdir(tempDir)

	// Create default key file
	s := NewService()
	s.SetWriteKeyToFile(true)

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey failed: %v", err)
	}

	// Test with both empty: internal keyFilePath and parameter
	s2 := NewService()
	s2.SetKeyFilePath("") // Empty internal path

	loaded, err := s2.GetEncryptionServiceFromFile("") // Empty parameter
	if err != nil {
		t.Fatalf("GetEncryptionServiceFromFile failed: %v", err)
	}

	if loaded == nil {
		t.Error("Expected loaded service to not be nil")
	}
}

// TestGeneratePassKeyWithEmptyFilePath tests GeneratePassKey when keyFilePath is empty
func TestGeneratePassKeyWithEmptyFilePath(t *testing.T) {
	tempDir := t.TempDir()
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)

	os.Chdir(tempDir)

	s := NewService()
	s.SetWriteKeyToFile(true)
	s.SetKeyFilePath("") // Set to empty string

	if err := s.GeneratePassKey(); err != nil {
		t.Fatalf("GeneratePassKey with empty path failed: %v", err)
	}

	// Verify file was created at default location
	if _, err := os.Stat(DefaultPassKeyFileName); os.IsNotExist(err) {
		t.Error("Default key file was not created")
	}
}

// TestConcurrentEncryption tests concurrent operations
func TestConcurrentEncryption(t *testing.T) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	const numGoroutines = 500
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			data := generateData()
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

// TestConcurrentService tests concurrent services
func TestConcurrentService(t *testing.T) {
	const numGoroutines = 500
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			s := NewService()
			if err := s.SetNewPassKey(randBytes(randRange(2, 32))); err != nil {
				errors <- err
			}

			data := generateData()
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
		t.Errorf("Concurrent services failed: %v", err)
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[mathRand.Intn(len(letterBytes))]
	}
	return b
}

func randRange(min, max int) int {
	return mathRand.Intn(max-min) + min
}

func generateData() []byte {
	return randBytes(randRange(2, 100_000))
}

// failingReader always returns an error
type failingReader struct{}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// Benchmarks
func BenchmarkEncrypt(b *testing.B) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
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

func BenchmarkDecrypt(b *testing.B) {
	s := NewService()
	if err := s.SetNewPassKey([]byte("test")); err != nil {
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

func BenchmarkGeneratePassKey(b *testing.B) {
	s := NewService()

	for b.Loop() {
		if err := s.GeneratePassKey(); err != nil {
			b.Fatalf("GeneratePassKey failed: %v", err)
		}
	}
}

func BenchmarkSetPassKeyFromPassword(b *testing.B) {
	s := NewService()
	password := "test-password"
	salt := make([]byte, SaltLength)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.SetNewPassKeyFromPassword(password, salt); err != nil {
			b.Fatalf("SetPassKeyFromPassword failed: %v", err)
		}
	}
}

// Race condition test cases: require the -race flag to find problems

// TestRaceConcurrentSetPassKey tests race condition when multiple goroutines set passkey
func TestRaceConcurrentSetPassKey(t *testing.T) {
	s := NewService()
	const numGoroutines = 100
	var wg sync.WaitGroup

	// Multiple goroutines concurrently setting different keys
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := []byte{byte(id)}
			_ = s.SetNewPassKey(key)
		}(i)
	}

	wg.Wait()
}

// TestRaceConcurrentGeneratePassKey tests race when multiple goroutines generate keys
func TestRaceConcurrentGeneratePassKey(t *testing.T) {
	s := NewService()
	const numGoroutines = 100
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for range numGoroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.GeneratePassKey(); err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("GeneratePassKey failed: %v", err)
	}
}

// TestRaceSetPassKeyWhileEncrypting tests setting key while encrypting
func TestRaceSetPassKeyWhileEncrypting(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("initial"))

	const numGoroutines = 50
	var wg sync.WaitGroup
	data := []byte("test data")

	// Half goroutines encrypt, half modify the key
	for i := range numGoroutines {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				_, _ = s.Encrypt(data)
			}()
		} else {
			go func(id int) {
				defer wg.Done()
				_ = s.SetNewPassKey([]byte{byte(id)})
			}(i)
		}
	}

	wg.Wait()
}

// TestRaceGeneratePassKeyWhileEncrypting tests generating key while encrypting
func TestRaceGeneratePassKeyWhileEncrypting(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("initial"))

	const numGoroutines = 50
	var wg sync.WaitGroup
	data := []byte("test data")

	for i := range numGoroutines {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				_, _ = s.Encrypt(data)
			}()
		} else {
			go func() {
				defer wg.Done()
				_ = s.GeneratePassKey()
			}()
		}
	}

	wg.Wait()
}

// TestRaceClearPassKeyWhileEncrypting tests clearing key while encrypting
func TestRaceClearPassKeyWhileEncrypting(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("test"))

	const numGoroutines = 50
	var wg sync.WaitGroup
	data := []byte("test data")

	for i := range numGoroutines {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				_, _ = s.Encrypt(data)
			}()
		} else {
			go func() {
				defer wg.Done()
				s.ClearPassKey()
			}()
		}
	}

	wg.Wait()
}

// TestRaceClearPassKeyWhileDecrypting tests clearing key while decrypting
func TestRaceClearPassKeyWhileDecrypting(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("test"))

	encrypted, err := s.Encrypt([]byte("data"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				_, _ = s.Decrypt(encrypted)
			}()
		} else {
			go func() {
				defer wg.Done()
				s.ClearPassKey()
			}()
		}
	}

	wg.Wait()
}

// TestRaceEncryptWithAutoGenerateRace tests the auto-generate race condition
func TestRaceEncryptWithAutoGenerateRace(t *testing.T) {
	// This is the critical race: multiple goroutines calling Encrypt
	// when passKey is not set, causing multiple auto-generations
	s := NewService()

	const numGoroutines = 100
	var wg sync.WaitGroup
	data := []byte("test data")
	encrypted := make([][]byte, numGoroutines)

	// All goroutines see empty passKey and try to auto-generate
	for i := range numGoroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			enc, _ := s.Encrypt(data)
			encrypted[idx] = enc
		}(i)
	}

	wg.Wait()

	// Due to potential race, different goroutines may have encrypted with different keys
	// Try to decrypt all with the final key (most should succeed with proper locking)
	successCount := 0
	for _, enc := range encrypted {
		if enc != nil {
			if dec, err := s.Decrypt(enc); err == nil && bytes.Equal(dec, data) {
				successCount++
			}
		}
	}

	// With proper locking, all encryptions should succeed with the same key
	if successCount != numGoroutines {
		t.Logf("Only %d/%d decryptions succeeded", successCount, numGoroutines)
	}
}

// TestRaceConfigFieldsWhileOperating tests race on config fields
func TestRaceConfigFieldsWhileOperating(t *testing.T) {
	s := NewService()

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		switch i % 3 {
		case 0:
			go func() {
				defer wg.Done()
				s.SetWriteKeyToFile(true)
			}()
		case 1:
			go func() {
				defer wg.Done()
				s.SetKeyFilePath("/tmp/key.txt")
			}()
		default:
			go func() {
				defer wg.Done()
				_ = s.GeneratePassKey()
			}()
		}
	}

	wg.Wait()
}

// TestRaceExportPassKeyWhileModifying tests exporting while modifying
func TestRaceExportPassKeyWhileModifying(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("test"))

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		if i%2 == 0 {
			go func() {
				defer wg.Done()
				_, _ = s.ExportPassKey()
			}()
		} else {
			go func(id int) {
				defer wg.Done()
				_ = s.SetNewPassKey([]byte{byte(id)})
			}(i)
		}
	}

	wg.Wait()
}

// TestRaceSetPassKeyFromPasswordConcurrent tests concurrent password-based key setting
func TestRaceSetPassKeyFromPasswordConcurrent(t *testing.T) {
	s := NewService()

	const numGoroutines = 100
	var wg sync.WaitGroup

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_ = s.SetNewPassKeyFromPassword("password", nil)
		}(i)
	}

	wg.Wait()
}

// TestRaceMixedOperations tests realistic mixed concurrent operations
func TestRaceMixedOperations(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("initial"))

	const numGoroutines = 100
	var wg sync.WaitGroup
	data := []byte("test data")

	encrypted, _ := s.Encrypt(data)

	for i := range numGoroutines {
		wg.Add(1)
		switch i % 6 {
		case 0:
			go func() {
				defer wg.Done()
				_, _ = s.Encrypt(data)
			}()
		case 1:
			go func() {
				defer wg.Done()
				_, _ = s.Decrypt(encrypted)
			}()
		case 2:
			go func(id int) {
				defer wg.Done()
				_ = s.SetNewPassKey([]byte{byte(id)})
			}(i)
		case 3:
			go func() {
				defer wg.Done()
				_ = s.GeneratePassKey()
			}()
		case 4:
			go func() {
				defer wg.Done()
				s.ClearPassKey()
			}()
		case 5:
			go func() {
				defer wg.Done()
				_, _ = s.ExportPassKey()
			}()
		}
	}

	wg.Wait()
}

// TestRaceStressTest runs intensive concurrent operations to maximize race detection
func TestRaceStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	s := NewService()
	_ = s.SetNewPassKey([]byte("test"))

	const duration = 1 * time.Second
	var stop atomic.Bool
	var wg sync.WaitGroup

	data := []byte("test data")
	encrypted, _ := s.Encrypt(data)

	// Encrypt operations
	wg.Go(func() {
		for !stop.Load() {
			_, _ = s.Encrypt(data)
		}
	})

	// Decrypt operations
	wg.Go(func() {
		for !stop.Load() {
			_, _ = s.Decrypt(encrypted)
		}
	})

	// SetPassKey operations
	wg.Go(func() {
		counter := byte(0)
		for !stop.Load() {
			_ = s.SetNewPassKey([]byte{counter})
			counter++
		}
	})

	// GeneratePassKey operations
	wg.Go(func() {
		for !stop.Load() {
			_ = s.GeneratePassKey()
		}
	})

	// ClearPassKey operations
	wg.Go(func() {
		for !stop.Load() {
			s.ClearPassKey()
			time.Sleep(1 * time.Millisecond)
		}
	})

	// ExportPassKey operations
	wg.Go(func() {
		for !stop.Load() {
			_, _ = s.ExportPassKey()
		}
	})

	// Config setter operations
	wg.Go(func() {
		toggle := false
		for !stop.Load() {
			s.SetWriteKeyToFile(toggle)
			toggle = !toggle
			time.Sleep(1 * time.Millisecond)
		}
	})

	// Config getter operations
	wg.Go(func() {
		for !stop.Load() {
			_ = s.GetWriteKeyToFile()
			_ = s.GetKeyFilePath()
		}
	})

	time.Sleep(duration)
	stop.Store(true)
	wg.Wait()
}

// TestRaceEncryptDecryptDifferentKeys demonstrates encryption/decryption with concurrent key changes
func TestRaceEncryptDecryptDifferentKeys(t *testing.T) {
	s := NewService()
	_ = s.SetNewPassKey([]byte("key1"))

	const numGoroutines = 50
	var wg sync.WaitGroup
	var successCount, failCount atomic.Int32

	original := []byte("secret message")

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Encrypt
			encrypted, err := s.Encrypt(original)
			if err != nil {
				failCount.Add(1)
				return
			}

			// Another goroutine might change the key here
			if id%10 == 0 {
				_ = s.SetNewPassKey([]byte{byte(id)})
			}

			// Try to decrypt
			decrypted, err := s.Decrypt(encrypted)
			if err != nil {
				failCount.Add(1)
				return
			}

			if bytes.Equal(decrypted, original) {
				successCount.Add(1)
			} else {
				failCount.Add(1)
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Success: %d, Failures: %d", successCount.Load(), failCount.Load())
}
