# xtsKryptor

xtsKryptor encrypts a file or folder as a versioned, authenticated AES-XTS
archive. It stores the input as an uncompressed TAR payload, encrypts that
payload sector by sector with AES-XTS, and authenticates the container with
HMAC-SHA256 before any decrypted data is extracted.

XTS is normally used for disk encryption. This project keeps XTS as the core
mode because that is the purpose of the repository, then adds the operational
pieces needed for a practical file and folder tool: passphrase-based key
derivation, random tweaks, authentication, safe TAR extraction checks,
overwrite protection, packaging, tests, and CI.

## Install

From a checkout:

```bash
python3 -m pip install -e .
```

For script-only use:

```bash
python3 -m pip install -r requirements.txt
python3 aes-xts-archive.py --help
```

## Quick Start

Encrypt a folder. The command prompts for a passphrase and asks for
confirmation:

```bash
xtskryptor encrypt ./my-folder --output ./my-folder.xts.aes
```

Decrypt it:

```bash
xtskryptor decrypt ./my-folder.xts.aes --output ./restored
```

The extracted output keeps the original top-level name. Decrypting
`./my-folder.xts.aes` into `./restored` creates `./restored/my-folder/...`.

The repository also keeps the original script name as a compatibility entry
point:

```bash
python3 aes-xts-archive.py encrypt ./photo.png --output ./photo.png.xts.aes
```

## Non-Interactive Use

Use a passphrase file:

```bash
printf '%s\n' 'use a long unique passphrase here' > passphrase.txt
chmod 600 passphrase.txt
xtskryptor encrypt ./data --output ./data.xts.aes --passphrase-file ./passphrase.txt
xtskryptor decrypt ./data.xts.aes --output ./restored --passphrase-file ./passphrase.txt
```

Or provide the passphrase through the environment:

```bash
export XTSKRYPTOR_PASSPHRASE='use a long unique passphrase here'
xtskryptor encrypt ./data --output ./data.xts.aes
```

Raw AES-XTS keys are supported for advanced users:

```bash
xtskryptor encrypt ./data \
  --raw-key-hex 0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210
```

The raw key must be 32 bytes for AES-128-XTS or 64 bytes for AES-256-XTS. The
two XTS key halves must be different.

## Inspect Metadata

Archive metadata can be inspected without a secret:

```bash
xtskryptor info ./data.xts.aes
xtskryptor info ./data.xts.aes --json
```

The output includes the format version, cipher, authentication method, KDF
parameters, sector size, and encrypted TAR payload size. It does not include
file names from the original folder because those are inside the encrypted TAR.

## Security Model

- Passphrases use Scrypt and derive separate AES-XTS and HMAC keys.
- Raw-key archives derive a separate HMAC key with HKDF-SHA256.
- Every archive uses a random 128-bit base tweak.
- Decryption verifies HMAC-SHA256 before extracting files.
- TAR members are checked for absolute paths, path traversal, unsafe link
  targets, unsupported member types, and accidental overwrites.

xtsKryptor protects archive contents and the TAR metadata inside the encrypted
payload. It does not hide the encrypted archive filename, encrypted size, host
filesystem timestamps, or metadata exposed by storage providers.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests
```

Run a local CLI roundtrip without installing:

```bash
XTSKRYPTOR_PASSPHRASE='test passphrase' \
  python3 aes-xts-archive.py encrypt ./README.md --output ./README.md.xts.aes

XTSKRYPTOR_PASSPHRASE='test passphrase' \
  python3 aes-xts-archive.py decrypt ./README.md.xts.aes --output ./restored
```

## License

MIT. See [LICENSE](LICENSE).
