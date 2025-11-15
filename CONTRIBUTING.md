# Contributing to Encryptor

First off, thank you for considering contributing to Encryptor! It's people like you that make this project great.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the [existing issues](https://github.com/AlexanderEl/encryptor/issues) to avoid duplicates.

When you create a bug report, please include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior**
- **Actual behavior**
- **Go version** (`go version`)
- **OS and architecture** (e.g., Linux amd64, macOS arm64)
- **Code sample** or test case that demonstrates the issue
- **Any relevant logs or error messages**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Clear title and description**
- **Motivation**: Why is this enhancement needed?
- **Detailed explanation** of the proposed functionality
- **Possible implementation approach** (if you have ideas)
- **Alternatives considered**

### Your First Code Contribution

Unsure where to begin? You can start by looking through these issues:

- **good first issue** - Issues that are good for newcomers
- **help wanted** - Issues that need assistance

### Pull Requests

We actively welcome your pull requests! Here's how to contribute:

1. Fork the repo and create your branch from `master`
2. Make your changes
3. Add tests for any new functionality
4. Ensure all tests pass
5. Update documentation
6. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.19 or higher
- Git

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/encryptor.git
cd encryptor

# Add upstream remote
git remote add upstream https://github.com/AlexanderEl/encryptor.git

# Install dependencies
go mod download

# Verify setup
go test ./...
```

### Building

```bash
# Build the library
go build

# Build the CLI tool
go build -o encryptor ./cmd/encryptor

# Or use Make
make build
```

## Pull Request Process

### Before Submitting

1. **Update your fork**
   ```bash
   git fetch upstream
   git rebase upstream/master
   ```

2. **Run tests**
   ```bash
   go test -race -v ./...
   ```

3. **Run linter**
   ```bash
   golangci-lint run
   # Or use Make
   make lint
   ```

4. **Check coverage**
   ```bash
   go test -cover ./...
   # Coverage should be > 90%
   ```

5. **Run benchmarks** (if you changed performance-critical code)
   ```bash
   go test -bench=. -benchmem ./...
   ```

### PR Requirements

Your pull request must:

- ✅ Pass all CI checks
- ✅ Include tests for new functionality
- ✅ Maintain or improve code coverage (>90%)
- ✅ Pass `go test -race` without any race conditions
- ✅ Update documentation (README, godoc comments)
- ✅ Follow the coding standards (see below)
- ✅ Have a clear description of what the PR does
- ✅ Reference related issues (e.g., "Fixes #123")

### PR Template

When creating a PR, please use this template:

```markdown
## Description
Brief description of what this PR does

## Related Issues
Fixes #(issue number)

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Checklist
- [ ] I have run `go test -race ./...` and all tests pass
- [ ] I have run `golangci-lint run` with no errors
- [ ] I have added tests that prove my fix/feature works
- [ ] Code coverage is maintained or improved
- [ ] I have updated the documentation accordingly
- [ ] I have added/updated examples if needed
- [ ] My code follows the style guidelines of this project
```

## Coding Standards

### Go Style Guide

Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

### Key Principles

1. **Simplicity**: Write simple, readable code
2. **Error Handling**: Always handle errors explicitly
3. **Naming**: Use clear, descriptive names
4. **Documentation**: Document all exported functions and types
5. **Thread Safety**: Ensure thread-safe operations where needed

### Code Formatting

```bash
# Format code
go fmt ./...

# Organize imports
goimports -w .

# Or use Make
make fmt
```

### Documentation

- All exported functions, types, and constants must have godoc comments
- Comments should start with the name of the thing being described
- Use complete sentences
- Include examples for non-trivial functionality

Example:
```go
// Encrypt encrypts the provided data using AES-256-GCM.
// It automatically generates a random nonce and prepends it to the ciphertext.
// If no encryption key is set, a new random key is generated automatically.
//
// Parameters:
//   - data: The plaintext data to encrypt
//
// Returns:
//   - Encrypted data with nonce prepended
//   - Error if encryption fails
func (s *Service) Encrypt(data []byte) ([]byte, error) {
    // implementation
}
```

## Testing Guidelines

### Test Requirements

1. **Unit Tests**: All new code must have unit tests
2. **Race Detection**: Tests must pass `go test -race`
3. **Coverage**: Maintain >90% code coverage
4. **Benchmarks**: Add benchmarks for performance-critical code

### Writing Tests

```go
func TestYourFeature(t *testing.T) {
    // Setup
    service := NewService()
    
    // Test cases using table-driven tests
    tests := []struct {
        name    string
        input   []byte
        want    []byte
        wantErr bool
    }{
        {
            name:    "valid input",
            input:   []byte("test"),
            want:    []byte("expected"),
            wantErr: false,
        },
        // More test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := service.YourMethod(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("YourMethod() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("YourMethod() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run with race detection
go test -race -v ./...

# Run with coverage
go test -cover -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test
go test -v -run TestYourFeature

# Run benchmarks
go test -bench=. -benchmem
```

### Race Condition Tests

For concurrent code, always add race condition tests:

```go
func TestRaceYourFeature(t *testing.T) {
    service := NewService()
    
    var wg sync.WaitGroup
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            // Perform concurrent operations
        }()
    }
    wg.Wait()
}
```

## Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, missing semicolons, etc.)
- **refactor**: Code refactoring without changing functionality
- **perf**: Performance improvements
- **test**: Adding or updating tests
- **chore**: Maintenance tasks (dependencies, CI, etc.)
- **security**: Security improvements

### Examples

```bash
feat(encryption): add support for ChaCha20-Poly1305

Add alternative encryption algorithm for better performance on
systems without AES hardware acceleration.

Closes #123

---

fix(key-derivation): correct PBKDF2 iteration count

The iteration count was incorrectly set to 10,000 instead of
100,000, reducing security. This fix corrects the value.

BREAKING CHANGE: Keys derived with the old iteration count will
no longer work. Users must regenerate their keys.

---

docs(readme): improve installation instructions

Add detailed steps for installing via go get and building from source.

---

test(encryption): add race condition tests

Ensure encryption operations are thread-safe by adding comprehensive
race detection tests.
```

## Branch Naming

Use descriptive branch names:

- `feature/add-chacha20-support`
- `fix/key-derivation-iteration-count`
- `docs/improve-readme`
- `refactor/simplify-error-handling`

## Questions?

Don't hesitate to ask! You can:

- Open an issue with the `question` label
- Start a discussion in [GitHub Discussions](https://github.com/AlexanderEl/encryptor/discussions)
- Email the maintainers (see README for contact info)

## Recognition

Contributors are recognized in:

- The project README (Contributors section)
- Release notes
- CHANGELOG.md

Thank you for contributing! 🎉
