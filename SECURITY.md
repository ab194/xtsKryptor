# Security Policy

## Supported Versions

Security fixes are accepted for the current `main` branch until the project
starts publishing stable release branches.

## Reporting a Vulnerability

Do not open a public issue for suspected cryptographic or extraction-safety
vulnerabilities. Use GitHub private vulnerability reporting if it is enabled
for the repository, or contact the maintainers privately.

A useful report includes:

- the affected xtsKryptor version or commit
- the operating system and Python version
- exact commands or API calls needed to reproduce the issue
- whether the issue requires a malicious archive, local filesystem access, or
  knowledge of a secret

## Design Limits

xtsKryptor uses AES-XTS because this repository is specifically about an XTS
file and folder encrypter. XTS is normally a disk-encryption mode, so the
container adds HMAC-SHA256 authentication and verifies the archive before
extracting files.

The encrypted payload hides file contents and TAR metadata, but it does not hide
the encrypted archive filename, file size, modification time on disk, or any
metadata exposed by your storage provider or operating system.

Passphrases are processed with Scrypt. Use long, unique passphrases or raw keys
from a cryptographically secure random generator.
