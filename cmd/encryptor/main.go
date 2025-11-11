package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AlexanderEl/encryptor"
)

const (
	version = "1.0.0"
	banner  = `
=========================================================
                                                         
    ███████╗███╗   ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██████╗
    ██╔════╝████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    █████╗  ██╔██╗ ██║██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██████╔╝
    ██╔══╝  ██║╚██╗██║██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██╔══██╗
    ███████╗██║ ╚████║╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝██║  ██║
    ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                                                         
         🔐 Secure File Encryption Tool v%s
                                                         
=========================================================
`
)

type Config struct {
	Operation   string
	FilePath    string
	OutputPath  string
	KeyFilePath string
	Verbose     bool
	ShowVersion bool
}

func main() {
	config := parseFlags()

	if config.ShowVersion {
		fmt.Printf("Encryptor CLI version %s\n", version)
		os.Exit(0)
	}

	if config.Verbose {
		fmt.Printf(banner, version)
	}

	if err := run(config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if config.Verbose {
		fmt.Println("\n✓ Operation completed successfully!")
	}
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.Operation, "op", "", "Operation: 'encrypt' or 'decrypt' (required)")
	flag.StringVar(&config.FilePath, "file", "", "Path to input file (required)")
	flag.StringVar(&config.OutputPath, "out", "", "Path to output file (default: input file + .enc or removes .enc)")
	flag.StringVar(&config.KeyFilePath, "key", "passkey.txt", "Path to passkey file")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.ShowVersion, "version", false, "Show version and exit")

	flag.Usage = printUsage
	flag.Parse()

	// Validate required flags
	if !config.ShowVersion && (config.Operation == "" || config.FilePath == "") {
		printUsage()
		os.Exit(1)
	}

	return config
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Encryptor CLI - Secure File Encryption Tool

Usage:
  encryptor -op <operation> -file <path> [options]

Operations:
  encrypt    Encrypt a file
  decrypt    Decrypt a file

Required Flags:
  -op string
        Operation: 'encrypt' or 'decrypt'
  -file string
        Path to input file

Optional Flags:
  -out string
        Path to output file (default: given file path)
  -key string
        Path to passkey file (default: "passkey.txt")
  -v    Verbose output
  -version
        Show version and exit

Examples:
  # Encrypt a file
  encryptor -op encrypt -file document.txt

  # Encrypt with custom output and key file
  encryptor -op encrypt -file document.txt -out secret.enc -key mykey.txt

  # Decrypt a file
  encryptor -op decrypt -file document.txt.enc

  # Decrypt with verbose output
  encryptor -op decrypt -file secret.enc -out decrypted.txt -v

Notes:
  - If passkey.txt doesn't exist during encryption, a new one will be generated
  - Keep your passkey.txt file secure - it's needed for decryption
  - Default output for encryption: <filename>.enc
  - Default output for decryption: removes .enc extension

`)
}

func run(config *Config) error {
	switch config.Operation {
	case "encrypt":
		return encryptFile(config)
	case "decrypt":
		return decryptFile(config)
	default:
		return fmt.Errorf("invalid operation '%s'. Use 'encrypt' or 'decrypt'", config.Operation)
	}
}

func encryptFile(config *Config) error {
	if config.Verbose {
		fmt.Printf("\n🔒 Encrypting file: %s\n", config.FilePath)
	}

	// Check if input file exists
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", config.FilePath)
	}

	// Read input file
	data, err := os.ReadFile(config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	if config.Verbose {
		fmt.Printf("   File size: %d bytes\n", len(data))
	}

	// Load or create encryption service
	service, isNewKey, err := getOrCreateService(config.KeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	if isNewKey && config.Verbose {
		fmt.Printf("   ✓ New encryption key generated and saved to: %s\n", config.KeyFilePath)
		fmt.Println("   ⚠️  Keep this key file secure - you'll need it for decryption!")
	} else if config.Verbose {
		fmt.Printf("   ✓ Using existing key from: %s\n", config.KeyFilePath)
	}

	// Encrypt data
	encrypted, err := service.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Determine output path
	outputPath := config.OutputPath
	if outputPath == "" {
		outputPath = config.FilePath + ".enc"
	}

	// Write encrypted file
	if err := os.WriteFile(outputPath, encrypted, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	if config.Verbose {
		fmt.Printf("   Encrypted size: %d bytes\n", len(encrypted))
		fmt.Printf("   ✓ Encrypted file saved to: %s\n", outputPath)
	} else {
		fmt.Printf("Encrypted: %s → %s\n", config.FilePath, outputPath)
	}

	return nil
}

func decryptFile(config *Config) error {
	if config.Verbose {
		fmt.Printf("\n🔓 Decrypting file: %s\n", config.FilePath)
	}

	// Check if input file exists
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", config.FilePath)
	}

	// Check if key file exists
	if _, err := os.Stat(config.KeyFilePath); os.IsNotExist(err) {
		return fmt.Errorf("passkey file not found: %s (needed for decryption)", config.KeyFilePath)
	}

	// Read encrypted file
	data, err := os.ReadFile(config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	if config.Verbose {
		fmt.Printf("   Encrypted size: %d bytes\n", len(data))
		fmt.Printf("   ✓ Using key from: %s\n", config.KeyFilePath)
	}

	// Load encryption service from key file
	service, err := encryptor.LoadEncryptionServiceFromFile(config.KeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to load encryption key: %w", err)
	}

	// Decrypt data
	decrypted, err := service.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decryption failed: %w (wrong key or corrupted file?)", err)
	}

	// Determine output path
	outputPath := config.OutputPath
	if outputPath == "" {
		// Try to remove .enc extension if present
		if filepath.Ext(config.FilePath) == ".enc" {
			outputPath = config.FilePath[:len(config.FilePath)-4]
		} else {
			outputPath = config.FilePath + ".dec"
		}
	}

	// Write decrypted file
	if err := os.WriteFile(outputPath, decrypted, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	if config.Verbose {
		fmt.Printf("   Decrypted size: %d bytes\n", len(decrypted))
		fmt.Printf("   ✓ Decrypted file saved to: %s\n", outputPath)
	} else {
		fmt.Printf("Decrypted: %s → %s\n", config.FilePath, outputPath)
	}

	return nil
}

// getOrCreateService is a helper function for getting the EncryptionService
// returns: the encryptorService, a flag for whether a new key is used or encountered error
func getOrCreateService(keyFilePath string) (*encryptor.Service, bool, error) {
	// Try to load existing key
	if _, err := os.Stat(keyFilePath); err == nil {
		service, err := encryptor.LoadEncryptionServiceFromFile(keyFilePath)
		if err != nil {
			return nil, false, err
		}
		return service, false, nil
	}

	// Create new service with key generation
	service := encryptor.NewService()
	service.WriteKeyToFile = true
	service.KeyFilePath = keyFilePath

	if err := service.GeneratePassKey(); err != nil {
		return nil, false, err
	}

	return service, true, nil
}
