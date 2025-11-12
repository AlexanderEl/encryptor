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
	if err := s.SetPassKey([]byte("test")); err != nil {
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
			err := s.SetPassKey(tt.key)

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

	if err := s.SetPassKeyFromPassword(password, salt); err != nil {
		t.Fatalf("SetPassKeyFromPassword failed: %v", err)
	}

	// Test with auto-generated salt
	s2 := NewService()
	if err := s2.SetPassKeyFromPassword(password, nil); err != nil {
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
	err := s3.SetPassKeyFromPassword("", nil)
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
	err := s.SetPassKeyFromPassword("password", nil)
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
	if err := s.SetPassKey([]byte("test")); err != nil {
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
	if err := s.SetPassKey([]byte("test")); err != nil {
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
	if err := s.SetPassKey([]byte("test")); err != nil {
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
	if err := s.SetPassKey([]byte("test")); err != nil {
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
	if err := s1.SetPassKey([]byte("key1")); err != nil {
		t.Fatalf("SetPassKey failed: %v", err)
	}

	original := []byte("secret")
	encrypted, err := s1.Encrypt(original)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	s2 := NewService()
	if err := s2.SetPassKey([]byte("key2")); err != nil {
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

	// Verify it's a copy
	exported[0] ^= 0xFF
	newExport, _ := s.ExportPassKey()
	if bytes.Equal(exported, newExport) {
		t.Error("ExportPassKey should return a copy")
	}
}

// TestClearPassKey tests securely clearing the passkey
func TestClearPassKey(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
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

// TestConcurrentEncryption tests concurrent operations
func TestConcurrentEncryption(t *testing.T) {
	s := NewService()
	if err := s.SetPassKey([]byte("test")); err != nil {
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
			if err := s.SetPassKey(randBytes(randRange(2, 32))); err != nil {
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
		if err := s.SetPassKeyFromPassword(password, salt); err != nil {
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
			_ = s.SetPassKey(key)
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
	_ = s.SetPassKey([]byte("initial"))

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
				_ = s.SetPassKey([]byte{byte(id)})
			}(i)
		}
	}

	wg.Wait()
}

// TestRaceGeneratePassKeyWhileEncrypting tests generating key while encrypting
func TestRaceGeneratePassKeyWhileEncrypting(t *testing.T) {
	s := NewService()
	_ = s.SetPassKey([]byte("initial"))

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
	_ = s.SetPassKey([]byte("test"))

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
	_ = s.SetPassKey([]byte("test"))

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
	_ = s.SetPassKey([]byte("test"))

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
				_ = s.SetPassKey([]byte{byte(id)})
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
			_ = s.SetPassKeyFromPassword("password", nil)
		}(i)
	}

	wg.Wait()
}

// TestRaceMixedOperations tests realistic mixed concurrent operations
func TestRaceMixedOperations(t *testing.T) {
	s := NewService()
	_ = s.SetPassKey([]byte("initial"))

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
				_ = s.SetPassKey([]byte{byte(id)})
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
	_ = s.SetPassKey([]byte("test"))

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
			_ = s.SetPassKey([]byte{counter})
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
	_ = s.SetPassKey([]byte("key1"))

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
				_ = s.SetPassKey([]byte{byte(id)})
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
