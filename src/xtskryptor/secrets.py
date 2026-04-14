"""Secret material parsing and derivation helpers."""

from __future__ import annotations

import binascii
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MAX_SCRYPT_N = 2**20
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 16
PASSPHRASE_KEY_BYTES = 96
XTS_256_KEY_BYTES = 64
MAC_KEY_BYTES = 32


@dataclass(frozen=True)
class Secret:
    """A passphrase or raw XTS key supplied by the caller."""

    kind: str
    value: bytes

    @classmethod
    def from_passphrase(cls, passphrase: str | bytes) -> "Secret":
        if isinstance(passphrase, str):
            passphrase = passphrase.encode("utf-8")
        if not passphrase:
            raise ValueError("passphrase must not be empty")
        return cls("passphrase", passphrase)

    @classmethod
    def from_raw_key(cls, key: bytes) -> "Secret":
        validate_xts_key(key)
        return cls("raw", key)


def raw_key_from_hex(value: str) -> bytes:
    """Parse a 32-byte or 64-byte XTS key from hexadecimal text."""

    compact = "".join(value.split())
    try:
        key = binascii.unhexlify(compact)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("raw XTS key must be valid hexadecimal text") from exc
    validate_xts_key(key)
    return key


def validate_xts_key(key: bytes) -> None:
    """Validate AES-XTS raw key material."""

    if len(key) not in (32, 64):
        raise ValueError(
            "raw AES-XTS key must be 32 bytes for AES-128-XTS or "
            "64 bytes for AES-256-XTS"
        )

    midpoint = len(key) // 2
    if key[:midpoint] == key[midpoint:]:
        raise ValueError("AES-XTS requires two different key halves")


def derive_passphrase_keys(
    passphrase: bytes,
    *,
    salt: bytes,
    n: int,
    r: int,
    p: int,
) -> tuple[bytes, bytes]:
    """Derive an AES-256-XTS key and HMAC key from a passphrase."""

    if n < 2 or n & (n - 1):
        raise ValueError("scrypt n must be a power of two greater than one")
    if r < 1 or p < 1:
        raise ValueError("scrypt r and p must be positive integers")
    if n > MAX_SCRYPT_N:
        raise ValueError(f"scrypt n must not exceed {MAX_SCRYPT_N}")
    if r > MAX_SCRYPT_R:
        raise ValueError(f"scrypt r must not exceed {MAX_SCRYPT_R}")
    if p > MAX_SCRYPT_P:
        raise ValueError(f"scrypt p must not exceed {MAX_SCRYPT_P}")

    kdf = Scrypt(
        salt=salt,
        length=PASSPHRASE_KEY_BYTES,
        n=n,
        r=r,
        p=p,
    )
    material = kdf.derive(passphrase)
    xts_key = material[:XTS_256_KEY_BYTES]
    mac_key = material[XTS_256_KEY_BYTES:]
    validate_xts_key(xts_key)
    return xts_key, mac_key


def derive_raw_mac_key(raw_key: bytes, *, salt: bytes) -> bytes:
    """Derive the HMAC key used to authenticate raw-key archives."""

    validate_xts_key(raw_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=MAC_KEY_BYTES,
        salt=salt,
        info=b"xtskryptor-v2 raw-key mac",
    ).derive(raw_key)
