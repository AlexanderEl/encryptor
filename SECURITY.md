# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of the encryptor project seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please do NOT:
- Open a public GitHub issue for security vulnerabilities
- Discuss the vulnerability in public forums, social media, or mailing lists before it has been addressed

### Please DO:
1. **Email us directly** at: [email][email]
2. Provide detailed information about the vulnerability:
   - Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
   - Full paths of source file(s) related to the manifestation of the issue
   - The location of the affected source code (tag/branch/commit or direct URL)
   - Any special configuration required to reproduce the issue
   - Step-by-step instructions to reproduce the issue
   - Proof-of-concept or exploit code (if possible)
   - Impact of the issue, including how an attacker might exploit it

## Response Timeline

- **Disclosure**: This is a public project with no guarantees of response times

## Security Update Process

1. The security issue is received and assigned to a primary handler
2. The problem is confirmed and affected versions are determined
3. Code is audited to find any similar problems
4. Fixes are prepared for all supported releases
5. Fixes are released and announcements are made

## Public Disclosure

After a security issue has been fixed, we will:
- Publish a security advisory on GitHub
- Credit the reporter (unless they wish to remain anonymous)
- Update the CHANGELOG with security fix details
- Announce the fix in the project README and release notes

## Security Best Practices for Users

When using the encryptor library:

1. **Key Management**
   - Never commit encryption keys to version control
   - Store keys in secure, encrypted storage
   - Use environment variables or secure key management services
   - Implement regular key rotation

2. **File Permissions**
   - Ensure key files have restrictive permissions (0600)
   - Store keys in protected directories
   - Limit access to encryption keys to necessary processes only

3. **Network Security**
   - Never transmit raw encryption keys over unsecured channels
   - Use TLS/SSL when transmitting encrypted data
   - Implement proper authentication before key exchange

4. **Dependencies**
   - Keep the encryptor library updated to the latest version
   - Regularly check for security updates
   - Monitor security advisories for golang.org/x/crypto

5. **Compliance**
   - Ensure your use case complies with relevant regulations (GDPR, HIPAA, etc.)
   - Implement proper audit logging
   - Follow your organization's security policies

## Security Features

The encryptor library implements the following security features:

- **AES-256-GCM**: Industry-standard authenticated encryption
- **PBKDF2**: Secure key derivation with 100,000 iterations
- **Unique Nonces**: Random nonce for each encryption operation
- **Authentication Tags**: Prevents tampering and ensures data integrity
- **Thread-Safety**: Safe for concurrent operations
- **Memory Protection**: Secure key clearing functionality

## Known Limitations

- This library is designed for data-at-rest encryption only
- Does not protect against attacks on the running process (memory dumps, debugging)
- Key security depends entirely on proper key management by the user
- Not suitable for end-to-end encrypted messaging (use specialized protocols)

## Security Audits

This project has not yet undergone a formal security audit. We welcome security researchers to review the code and report any findings.

## Contact

For security-related questions or concerns, contact: [email][email]

## Attribution

We appreciate the security research community and will acknowledge security researchers who responsibly disclose vulnerabilities.

---

**PGP Key**: (Optional - add your PGP public key fingerprint here for encrypted communications)

[email]: alexanderel.able734@passinbox.com
