# 🔐 Encryptor

[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat&logo=go)](https://golang.org/doc/devel/release.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/AlexanderEl/encryptor)](https://goreportcard.com/report/github.com/AlexanderEl/encryptor)

A lightweight, secure, and fast encryption service for Go applications using AES-256-GCM encryption.

## ✨ Features

- 🔒 **AES-256-GCM Encryption** - Industry-standard authenticated encryption
- 🔑 **Flexible Key Management** - Support for random keys, user passwords, and file-based keys
- 🛡️ **PBKDF2 Key Derivation** - Secure password-to-key transformation
- 📁 **Secure File Storage** - Keys stored with restrictive permissions (0600)
- ⚡ **High Performance** - Optimized for speed with minimal overhead
- 🧵 **Thread-Safe** - 100% safe for concurrent operations with comprehensive race testing
- ✅ **Comprehensive Testing** - 95%+ test coverage with benchmarks and race detection
- 📦 **Zero Dependencies** - Uses only Go standard library + `golang.org/x/crypto`

## 📦 Installation

```bash
go get github.com/AlexanderEl/encryptor
```

## 🚀 Quick Start

### Command Line Tool

The easiest way to get started is using the CLI tool for encrypting and decrypting files:

```bash
# Clone the repository
git clone https://github.com/AlexanderEl/encryptor.git
cd encryptor

# Build the CLI tool
go build -o encryptor cmd/encryptor/main.go

# Encrypt a file (automatically generates passkey.txt)
./encryptor -op encrypt -file document.txt

# Decrypt the file (uses existing passkey.txt)
./encryptor -op decrypt -file document.txt.enc
```

See the [CLI Usage](#-cli-usage) section for complete documentation.

### Library Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/AlexanderEl/encryptor"
)

func main() {
    // Create a new encryption service
    service := encryptor.NewService()
    
    // Set a passkey (will be automatically padded/derived to 32 bytes)
    if err := service.SetPassKey([]byte("my-secret-key")); err != nil {
        log.Fatal(err)
    }
    
    // Encrypt data
    plaintext := []byte("super secret message")
    encrypted, err := service.Encrypt(plaintext)
    if err != nil {
        log.Fatal(err)
    }
    
    // Decrypt data
    decrypted, err := service.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Original:  %s\n", plaintext)
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Auto-Generated Keys

```go
// Let the service generate a secure random key
service := encryptor.NewService()

encrypted, err := service.Encrypt([]byte("secret data"))
// Key is automatically generated on first encryption
```

### Password-Based Encryption

```go
service := encryptor.NewService()

// Derive a secure key from a password using PBKDF2
password := "user-password-123"
if err := service.SetPassKeyFromPassword(password, nil); err != nil {
    log.Fatal(err)
}

encrypted, err := service.Encrypt([]byte("sensitive data"))
```

### Persistent Key Storage

```go
// Generate and save key to file
service := encryptor.NewService()
service.SetWriteKeyToFile(true)
service.SetKeyFilePath("my-secret-key.txt")

if err := service.GeneratePassKey(); err != nil {
    log.Fatal(err)
}

// Later, load the key from file
loadedService, err := encryptor.LoadEncryptionServiceFromFile("my-secret-key.txt")
if err != nil {
    log.Fatal(err)
}
```

## 🖥️ CLI Usage

The encryptor comes with a command-line interface for easy file encryption and decryption.

### Building the CLI

```bash
# Clone the repository
git clone https://github.com/AlexanderEl/encryptor.git
cd encryptor

# Build the CLI tool
go build -o encryptor cmd/encryptor/main.go

# Optionally, install it to your PATH
go install github.com/AlexanderEl/encryptor/cmd/encryptor@latest
```

### Command Syntax

```bash
encryptor -op <operation> -file <path> [options]
```

### Available Flags

| Flag | Description | Required | Default |
|------|-------------|----------|---------|
| `-op` | Operation: `encrypt` or `decrypt` | Yes | - |
| `-file` | Path to input file | Yes | - |
| `-out` | Path to output file | No | Auto-generated |
| `-key` | Path to passkey file | No | `passkey.txt` |
| `-v` | Verbose output | No | `false` |
| `-version` | Show version and exit | No | `false` |

### Encryption Examples

```bash
# Basic encryption (creates passkey.txt automatically)
./encryptor -op encrypt -file document.txt
# Output: document.txt.enc

# Encrypt with verbose output
./encryptor -op encrypt -file confidential.pdf -v
# Shows detailed progress and warnings

# Encrypt with custom output path
./encryptor -op encrypt -file data.json -out encrypted_data.bin

# Encrypt using a specific key file
./encryptor -op encrypt -file report.docx -key my-secret-key.txt

# Encrypt multiple files (bash example)
for file in *.txt; do
    ./encryptor -op encrypt -file "$file"
done
```

### Decryption Examples

```bash
# Basic decryption (uses existing passkey.txt)
./encryptor -op decrypt -file document.txt.enc
# Output: document.txt

# Decrypt with verbose output
./encryptor -op decrypt -file confidential.pdf.enc -v

# Decrypt to a specific location
./encryptor -op decrypt -file encrypted_data.bin -out original_data.json

# Decrypt using a specific key file
./encryptor -op decrypt -file report.docx.enc -key my-secret-key.txt

# Decrypt multiple files (bash example)
for file in *.enc; do
    ./encryptor -op decrypt -file "$file"
done
```

### CLI Output Behavior

**Default Output Paths:**
- **Encryption**: Adds `.enc` extension
  - `document.txt` → `document.txt.enc`
- **Decryption**: Removes `.enc` extension or adds `.dec`
  - `document.txt.enc` → `document.txt`
  - `document.bin` → `document.bin.dec`

**Normal Mode (default):**
```bash
$ ./encryptor -op encrypt -file test.txt
Encrypted: test.txt → test.txt.enc
```

**Verbose Mode (`-v` flag):**
```bash
$ ./encryptor -op encrypt -file test.txt -v

=========================================================
                                                         
    ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗
    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██████╔╝
    ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗
    ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║
    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                         
         🔐 Secure File Encryption Tool v1.0.0
                                                         
=========================================================

🔒 Encrypting file: test.txt
   File size: 1234 bytes
   ✓ New encryption key generated and saved to: passkey.txt
   ⚠️  Keep this key file secure - you'll need it for decryption!
   Encrypted size: 1262 bytes
   ✓ Encrypted file saved to: test.txt.enc

✓ Operation completed successfully!
```

### CLI Error Messages

The CLI provides clear error messages for common issues:

```bash
# Missing input file
$ ./encryptor -op encrypt -file nonexistent.txt
Error: input file does not exist: nonexistent.txt

# Missing key file for decryption
$ ./encryptor -op decrypt -file document.txt.enc
Error: passkey file not found: passkey.txt (needed for decryption)

# Wrong key or corrupted file
$ ./encryptor -op decrypt -file document.txt.enc
Error: decryption failed: cipher: message authentication failed (wrong key or corrupted file?)

# Invalid operation
$ ./encryptor -op invalid -file test.txt
Error: invalid operation 'invalid'. Use 'encrypt' or 'decrypt'
```

### CLI Best Practices

1. **Keep Your Key File Safe**
   ```bash
   # After encrypting, backup your key file
   cp passkey.txt ~/secure-backup/passkey-backup.txt

   # Set restrictive permissions
   chmod 600 passkey.txt
   ```

2. **Batch Processing**
   ```bash
   # Encrypt all text files in a directory
   find . -name "*.txt" -exec ./encryptor -op encrypt -file {} \;

   # Decrypt all encrypted files
   find . -name "*.enc" -exec ./encryptor -op decrypt -file {} \;
   ```

3. **Use Different Keys for Different Projects**
   ```bash
   # Project A
   ./encryptor -op encrypt -file project-a-data.txt -key keys/project-a.txt

   # Project B
   ./encryptor -op encrypt -file project-b-data.txt -key keys/project-b.txt
   ```

4. **Verify Encryption Worked**
   ```bash
   # Encrypt a file
   ./encryptor -op encrypt -file important.txt

   # Try to view encrypted file (should be unreadable)
   cat important.txt.enc

   # Decrypt and verify
   ./encryptor -op decrypt -file important.txt.enc -out verified.txt
   diff important.txt verified.txt
   ```

### Integration with Scripts

```bash
#!/bin/bash
# backup-and-encrypt.sh

BACKUP_DIR="/backup"
KEY_FILE="$HOME/.secrets/backup-key.txt"

# Create backup
tar -czf backup.tar.gz /important/data

# Encrypt backup
./encryptor -op encrypt -file backup.tar.gz -key "$KEY_FILE"

# Remove unencrypted backup
rm backup.tar.gz

# Move to backup location
mv backup.tar.gz.enc "$BACKUP_DIR/backup-$(date +%Y%m%d).tar.gz.enc"

echo "Backup completed and encrypted successfully!"
```

## 📖 API Documentation

### Core Methods

#### `NewService() *Service`
Creates a new encryption service with default settings.

#### `SetPassKey(key []byte) error`
Sets the encryption key. Keys shorter than 32 bytes are securely derived using PBKDF2.

**Parameters:**
- `key` - Encryption key (max 32 bytes)

**Returns:** Error if key is empty or exceeds 32 bytes

#### `SetPassKeyFromPassword(password string, salt []byte) error`
Derives a secure 32-byte key from a password using PBKDF2 with 100,000 iterations.

**Parameters:**
- `password` - User password
- `salt` - Optional salt (auto-generated if nil)

**Returns:** Error if password is empty

#### `Encrypt(data []byte) ([]byte, error)`
Encrypts data using AES-256-GCM. Auto-generates a key if not set.

**Parameters:**
- `data` - Plaintext to encrypt

**Returns:** Encrypted data with prepended nonce, or error

#### `Decrypt(data []byte) ([]byte, error)`
Decrypts AES-256-GCM encrypted data.

**Parameters:**
- `data` - Ciphertext to decrypt

**Returns:** Decrypted plaintext, or error

#### `GeneratePassKey() error`
Generates a cryptographically secure random 32-byte key.

**Returns:** Error on failure

#### `ExportPassKey() ([]byte, error)`
Returns a **copy** of the current encryption key. Use with caution.

**Returns:** Key copy, or error if key not set

#### `ClearPassKey()`
Securely zeros out the key from memory.

### Configuration Methods

#### `SetWriteKeyToFile(write bool)`
Thread-safe setter to enable/disable writing keys to file.

#### `GetWriteKeyToFile() bool`
Thread-safe getter for the write-to-file setting.

#### `SetKeyFilePath(path string)`
Thread-safe setter for the key file path.

#### `GetKeyFilePath() string`
Thread-safe getter for the key file path.

### File Operations

#### `LoadEncryptionServiceFromFile(filePath string) (*Service, error)`
Convenience function to load an encryption service from a key file.

**Parameters:**
- `filePath` - Path to key file

**Returns:** Service instance, or error

## 🔧 Configuration

### Service Options

```go
service := encryptor.NewService()

// Write generated keys to file
service.SetWriteKeyToFile(true)

// Custom key file location
service.SetKeyFilePath("/secure/path/encryption.key")
```

### Constants

```go
const (
    KeyByteLength         = 32      // AES-256 key size
    DefaultPassKeyFileName = "passkey.txt"
    FilePermissions       = 0600    // Owner read/write only
    PBKDF2Iterations      = 100000  // Key derivation iterations
    SaltLength            = 16      // Salt size in bytes
)
```

## 🔒 Security Features

### Encryption Algorithm
- **AES-256-GCM** - Authenticated encryption with associated data (AEAD)
- **Unique Nonces** - Random nonce for each encryption operation
- **Authentication Tags** - Prevents tampering and ensures data integrity

### Key Management
- **PBKDF2 Key Derivation** - SHA-256 with 100,000 iterations
- **Secure Random Generation** - Uses `crypto/rand` for key generation
- **Memory Protection** - `ClearPassKey()` zeros memory before cleanup
- **File Permissions** - Keys stored with 0600 (owner-only access)

### Thread Safety
- **Full Concurrency Support** - All operations are thread-safe with optimized locking
- **Race Condition Free** - Extensively tested with Go's race detector
- **Minimal Lock Duration** - Expensive operations performed outside critical sections
- **Memory-Safe Key Management** - Protected copying prevents concurrent modification issues

### Best Practices
✅ Never reuse keys across different applications  
✅ Store key files in secure locations with restricted permissions  
✅ Use password-based keys with strong, unique passwords  
✅ Call `ClearPassKey()` when done with sensitive operations  
✅ Never log or transmit raw encryption keys  
✅ Safe for concurrent use in multi-threaded applications

## ⚡ Performance

**Quick Reference:**

| Operation | Speed | Throughput |
|-----------|-------|------------|
| Encrypt | 628 ns/op | ~1.6M ops/sec |
| Decrypt | 531 ns/op | ~1.9M ops/sec |
| Key Generation | 91 ns/op | ~11M ops/sec |
| Password Derivation | 11.2 ms/op | Security feature |

Benchmarks on Intel Core i9-14900HX (with thread-safe locking):

```
TEST_NAME                             ITERATIONS  AVG_ITER_DURATION    MEMORY_USED  NUM_MEMORY_ALLOCATIONS
BenchmarkEncrypt-32                      1883298        627.6 ns/op      1376 B/op       4 allocs/op
BenchmarkDecrypt-32                      2254128        531.4 ns/op      1328 B/op       3 allocs/op
BenchmarkGeneratePassKey-32             13150389        91.21 ns/op        32 B/op       1 allocs/op
BenchmarkSetPassKeyFromPassword-32           100     11237741 ns/op       788 B/op      11 allocs/op
```

**Performance Highlights:**
- ⚡ **Encryption**: ~628 ns/op (~1.6 million ops/sec) - Thread-safe with minimal overhead
- ⚡ **Decryption**: ~531 ns/op (~1.9 million ops/sec) - Optimized concurrent access
- ⚡ **Key Generation**: ~91 ns/op (~11 million ops/sec) - Lock-free random generation
- 🔐 **Password Derivation**: ~11.2 ms/op (intentionally slow for security - 100k PBKDF2 iterations)

**Thread-Safety Impact:**
The implementation uses optimized read-write locking (`sync.RWMutex`) for safe concurrent access:
- Read operations (encryption/decryption) can run concurrently
- Write operations (key setting) have minimal lock duration
- Expensive cryptographic operations performed outside critical sections
- The baseline implementation was highly optimized (~420ns per encryption), operating near the theoretical limits of AES-GCM performance. Even minimal synchronization overhead becomes proportionally significant at this performance tier
- Despite the relative overhead, absolute performance remains exceptional at ~1.6-1.9 million operations per second, making this trade-off worthwhile for production applications requiring concurrent access

**Note**: Password-based key derivation is intentionally slow to protect against brute-force attacks. This is a security feature, not a performance issue.

## 🧪 Testing

The encryptor package includes comprehensive testing with multiple test categories.

### Basic Testing

```bash
# Run all tests
go test -v

# Run tests with coverage
go test -cover

# Generate detailed coverage report
go test -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run specific test
go test -v -run TestEncryptDecrypt

# Run benchmarks
go test -bench=. -benchmem
```

### Race Condition Testing

The package includes extensive race condition tests to ensure 100% thread-safety. These tests use Go's built-in race detector to identify data races.

```bash
# Run ALL tests with race detection (RECOMMENDED)
go test -race

# Run tests with race detection and verbose output
go test -race -v

# Run only race-specific tests
go test -race -v -run Race

# Run race tests with coverage
go test -race -cover

# Run intensive stress test (takes ~1 second)
go test -race -v -run TestRaceStressTest
```

**Race Test Categories:**

1. **Concurrent Key Operations**
   - `TestRaceConcurrentSetPassKey` - Multiple goroutines setting different keys
   - `TestRaceConcurrentGeneratePassKey` - Concurrent key generation
   - `TestRaceSetPassKeyFromPasswordConcurrent` - Password-based key derivation races

2. **Key Operations During Encryption/Decryption**
   - `TestRaceSetPassKeyWhileEncrypting` - Key changes during encryption
   - `TestRaceGeneratePassKeyWhileEncrypting` - Key generation during encryption
   - `TestRaceClearPassKeyWhileEncrypting` - Clearing key during encryption
   - `TestRaceClearPassKeyWhileDecrypting` - Clearing key during decryption

3. **Auto-Generation Races**
   - `TestRaceEncryptWithAutoGenerateRace` - Multiple encryptions triggering auto-generation

4. **Configuration Field Races**
   - `TestRaceConfigFieldsWhileOperating` - Concurrent config changes during operations
   - `TestRaceExportPassKeyWhileModifying` - Exporting key while modifying

5. **Mixed Operations**
   - `TestRaceMixedOperations` - Realistic concurrent usage patterns
   - `TestRaceStressTest` - Intensive continuous operations for 1 second

6. **Different Keys Scenario**
   - `TestRaceEncryptDecryptDifferentKeys` - Encryption/decryption with concurrent key changes

### Continuous Integration Testing

```bash
# Complete CI test suite (what should run in CI/CD)
go test -race -cover -v -timeout 30s

# With JSON output for CI tools
go test -race -cover -json > test-results.json
```

### Test Coverage

The package maintains 95%+ test coverage across:
- ✅ All public API methods
- ✅ Error conditions and edge cases
- ✅ Concurrent operations
- ✅ File I/O operations
- ✅ Race conditions
- ✅ Memory safety

### Performance Testing

```bash
# Run all benchmarks
go test -bench=.

# Run specific benchmark
go test -bench=BenchmarkEncrypt

# Run benchmarks with memory allocation stats
go test -bench=. -benchmem

# Run benchmarks multiple times for accuracy
go test -bench=. -benchtime=10s -count=5

# Compare benchmarks (requires benchstat tool)
go test -bench=. -benchmem > old.txt
# Make changes...
go test -bench=. -benchmem > new.txt
benchstat old.txt new.txt
```

### Testing Best Practices

1. **Always Run Race Detection Locally**
   ```bash
   # Before committing code
   go test -race -v
   ```

2. **Test Concurrent Scenarios**
   ```bash
   # Run stress tests multiple times
   for i in {1..10}; do go test -race -run TestRaceStressTest; done
   ```

3. **Check for Memory Leaks**
   ```bash
   go test -bench=. -benchmem -memprofile=mem.out
   go tool pprof mem.out
   ```

4. **Verify Coverage**
   ```bash
   go test -cover -coverprofile=coverage.out
   go tool cover -func=coverage.out | grep total
   ```

### Expected Test Results

When all tests pass, you should see:
```
PASS
coverage: 95%+ of statements
ok      github.com/AlexanderEl/encryptor    12.456s
```

**Warning Signs:**
- ⚠️ `WARNING: DATA RACE` - Indicates a race condition (should not occur)
- ⚠️ Coverage below 90% - May indicate untested code paths
- ⚠️ Benchmark performance degradation >10% - May indicate performance regression

## 📋 Examples

### Example 1: Secure File Encryption

```go
package main

import (
    "io/ioutil"
    "log"
    
    "github.com/AlexanderEl/encryptor"
)

func encryptFile(inputPath, outputPath, keyPath string) error {
    // Read file
    data, err := ioutil.ReadFile(inputPath)
    if err != nil {
        return err
    }
    
    // Load or create encryption service
    var service *encryptor.Service
    service, err = encryptor.LoadEncryptionServiceFromFile(keyPath)
    if err != nil {
        // Create new service if key doesn't exist
        service = encryptor.NewService()
        service.SetWriteKeyToFile(true)
        service.SetKeyFilePath(keyPath)
        if err := service.GeneratePassKey(); err != nil {
            return err
        }
    }
    
    // Encrypt
    encrypted, err := service.Encrypt(data)
    if err != nil {
        return err
    }
    
    // Write encrypted file
    return ioutil.WriteFile(outputPath, encrypted, 0644)
}
```

### Example 2: Multi-User Encryption (Thread-Safe)

```go
package main

import (
    "sync"
    
    "github.com/AlexanderEl/encryptor"
)

type UserEncryptor struct {
    mu       sync.RWMutex
    services map[string]*encryptor.Service
}

func NewUserEncryptor() *UserEncryptor {
    return &UserEncryptor{
        services: make(map[string]*encryptor.Service),
    }
}

func (u *UserEncryptor) EncryptForUser(userID string, data []byte) ([]byte, error) {
    u.mu.RLock()
    service, exists := u.services[userID]
    u.mu.RUnlock()
    
    if !exists {
        service = encryptor.NewService()
        if err := service.GeneratePassKey(); err != nil {
            return nil, err
        }
        
        u.mu.Lock()
        u.services[userID] = service
        u.mu.Unlock()
    }
    
    // Service itself is thread-safe
    return service.Encrypt(data)
}
```

### Example 3: Environment-Based Keys

```go
package main

import (
    "encoding/hex"
    "errors"
    "os"
    
    "github.com/AlexanderEl/encryptor"
)

func getServiceFromEnv() (*encryptor.Service, error) {
    keyHex := os.Getenv("ENCRYPTION_KEY")
    if keyHex == "" {
        return nil, errors.New("ENCRYPTION_KEY not set")
    }
    
    key, err := hex.DecodeString(keyHex)
    if err != nil {
        return nil, err
    }
    
    service := encryptor.NewService()
    if err := service.SetPassKey(key); err != nil {
        return nil, err
    }
    
    return service, nil
}
```

### Example 4: Concurrent Processing

```go
package main

import (
    "io/ioutil"
    "sync"
    
    "github.com/AlexanderEl/encryptor"
)

func encryptMultipleFiles(files []string, service *encryptor.Service) error {
    var wg sync.WaitGroup
    errChan := make(chan error, len(files))
    
    // Process files concurrently - service is thread-safe
    for _, file := range files {
        wg.Add(1)
        go func(f string) {
            defer wg.Done()
            
            data, err := ioutil.ReadFile(f)
            if err != nil {
                errChan <- err
                return
            }
            
            encrypted, err := service.Encrypt(data)
            if err != nil {
                errChan <- err
                return
            }
            
            if err := ioutil.WriteFile(f+".enc", encrypted, 0644); err != nil {
                errChan <- err
            }
        }(file)
    }
    
    wg.Wait()
    close(errChan)
    
    // Check for errors
    if err := <-errChan; err != nil {
        return err
    }
    
    return nil
}
```

## ❌ Error Handling

The service defines several sentinel errors for clear error handling:

```go
var (
    ErrEmptyPassKey      = errors.New("passkey cannot be empty")
    ErrPassKeyTooLong    = errors.New("passkey exceeds maximum length of 32 bytes")
    ErrEmptyData         = errors.New("data cannot be empty")
    ErrInvalidCiphertext = errors.New("ciphertext too short")
    ErrPassKeyNotSet     = errors.New("passkey not set")
)
```

### Usage

```go
service := encryptor.NewService()
_, err := service.Decrypt(data)

if errors.Is(err, encryptor.ErrPassKeyNotSet) {
    // Handle missing key
    service.GeneratePassKey()
} else if errors.Is(err, encryptor.ErrInvalidCiphertext) {
    // Handle corrupted data
    log.Println("Data appears to be corrupted")
}
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/encryptor.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes and add tests
5. Run tests with race detection: `go test -race -v`
6. Ensure coverage stays above 90%: `go test -cover`
7. Validate performance with justification for any reduction: `go test -bench=. -benchmem`
8. Commit your changes: `git commit -m 'Add amazing feature'`
9. Push to the branch: `git push origin feature/amazing-feature`
10. Open a Pull Request

### Code Standards

- Follow [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Add tests for new functionality (including race tests if concurrent)
- Maintain test coverage above 90%
- All new code must pass `go test -race`
- Update documentation for API changes
- Run `go fmt` and `go vet` before committing
- Optimize for minimal lock duration in concurrent code

### Testing Requirements

All pull requests must:
- ✅ Pass `go test -race` without any race conditions
- ✅ Maintain or improve test coverage
- ✅ Include benchmarks for performance-critical changes
- ✅ Pass all existing tests

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Uses Go's excellent `crypto/aes` and `crypto/cipher` packages
- Key derivation powered by `golang.org/x/crypto/pbkdf2`
- Inspired by best practices from [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## 📞 Support

- 🐛 **Bug Reports**: [Open an issue](https://github.com/AlexanderEl/encryptor/issues)
- 💡 **Feature Requests**: [Open an issue](https://github.com/AlexanderEl/encryptor/issues)
- 📧 **Email**: [Your email if you want to include it]
- 💬 **Discussions**: [GitHub Discussions](https://github.com/AlexanderEl/encryptor/discussions)

## ⚠️ Security Considerations

### When to Use This Library
✅ Encrypting data at rest  
✅ Protecting sensitive configuration  
✅ Secure file storage  
✅ Application-level encryption  
✅ Multi-threaded/concurrent applications

### When NOT to Use This Library
❌ TLS/SSL connections (use `crypto/tls`)  
❌ Password hashing (use `bcrypt` or `argon2`)  
❌ Digital signatures (use `crypto/rsa` or `crypto/ecdsa`)  
❌ End-to-end messaging (use specialized protocols)

### Important Security Notes

- **Key Management**: The security of your encrypted data depends entirely on the security of your keys. Never commit keys to version control.
- **Key Rotation**: Implement regular key rotation for long-lived applications.
- **Compliance**: Ensure your use case complies with relevant regulations (GDPR, HIPAA, etc.).
- **Threat Model**: This library protects data at rest. It does not protect against attacks on the running process.
- **Thread Safety**: All operations are safe for concurrent use, but key management operations will briefly block other operations.

## 🗺️ Roadmap

- [ ] Add Argon2 support for password-based key derivation
- [ ] Implement key rotation mechanism
- [ ] Add streaming encryption for large files
- [ ] Support for multiple encryption algorithms
- [ ] Built-in key management service integration (AWS KMS, Vault)
- [ ] Add context support for cancellable operations
- [x] Provide CLI tool for file encryption
- [x] 100% thread-safe implementation with comprehensive race testing

## 📊 Version History

### v1.0.1 (Current)
- ✨ 100% thread-safe code with optimized locking strategy
- 🧪 Comprehensive race condition test suite (15+ race-specific tests)
- 🔒 Thread-safe configuration getters/setters
- 🚀 Maintains high performance (~1.6-1.9M ops/sec) despite thread-safety overhead
- 📝 Updated documentation with testing guidelines
- 🐛 Fixed race condition in key generation and file writing
- ✅ All operations verified safe under Go race detector

### v1.0.0
- Initial release with AES-256-GCM encryption
- PBKDF2 key derivation
- File-based key management
- Comprehensive test suite

---

**Made with ❤️ by the Encryptor Team**

*If you find this library useful, please consider giving it a ⭐ on GitHub!*