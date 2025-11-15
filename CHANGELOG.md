# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- CI/CD pipeline with GitHub Actions
- Comprehensive linting configuration with golangci-lint
- Security scanning with Gosec
- SECURITY.md for responsible disclosure
- CHANGELOG.md for tracking changes
- Issue and PR templates
- CODE_OF_CONDUCT.md
- CONTRIBUTING.md with detailed guidelines
- Examples directory with runnable code samples
- Makefile for common development tasks
- Docker support
- Fuzzing tests for encryption functions

### Changed
- Improved README with better examples
- Enhanced documentation for key management

### Fixed
- None

## [1.1.0] - 2024-01-15

### Added
- Key export/import functionality via `ExportPassKey()` and `SetExportedKey()`
- Support for sharing keys across distributed systems
- Distinguish between derived keys (`SetNewPassKey`) and raw keys (`SetExportedKey`)
- Comprehensive examples for key export/import workflows
- Extended test coverage for key export/import scenarios
- Validation for minimum key size (16 bytes for AES-128)

### Changed
- Updated documentation with key management best practices
- Enhanced API documentation for key-related methods

### Fixed
- Added proper validation for minimum key size

## [1.0.1] - 2024-01-10

### Added
- 100% thread-safe code with optimized locking strategy
- Comprehensive race condition test suite (15+ race-specific tests)
- Thread-safe configuration getters/setters
- Updated documentation with testing guidelines

### Changed
- Optimized locking strategy for minimal performance impact
- Maintains high performance (~1.6-1.9M ops/sec) despite thread-safety overhead

### Fixed
- Fixed race condition in key generation and file writing
- All operations verified safe under Go race detector

### Security
- Improved thread safety for concurrent operations

## [1.0.0] - 2024-01-01

### Added
- Initial release with AES-256-GCM encryption
- PBKDF2 key derivation with 100,000 iterations
- File-based key management with secure permissions (0600)
- Comprehensive test suite with 95%+ coverage
- Support for random keys, user passwords, and exported keys
- CLI tool for file encryption/decryption
- Benchmarking suite
- MIT License

### Security
- AES-256-GCM authenticated encryption
- Secure key derivation using PBKDF2-SHA256
- Memory protection with secure key clearing
- Thread-safe operations

## [0.1.0] - 2023-12-15

### Added
- Initial proof-of-concept
- Basic AES encryption/decryption
- Simple key management

---

## Version Naming Convention

- **Major version**: Incompatible API changes
- **Minor version**: Backwards-compatible new features
- **Patch version**: Backwards-compatible bug fixes

## Links

- [Unreleased]: https://github.com/AlexanderEl/encryptor/compare/v1.1.0...HEAD
- [1.1.0]: https://github.com/AlexanderEl/encryptor/compare/v1.0.1...v1.1.0
- [1.0.1]: https://github.com/AlexanderEl/encryptor/compare/v1.0.0...v1.0.1
- [1.0.0]: https://github.com/AlexanderEl/encryptor/releases/tag/v1.0.0