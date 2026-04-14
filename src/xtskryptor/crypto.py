"""Versioned AES-XTS archive container implementation."""

from __future__ import annotations

import base64
import json
import os
import secrets
import struct
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .archive import add_path_to_tar, extract_tar_archive, validate_encrypt_paths
from .exceptions import ArchiveFormatError, AuthenticationError
from .secrets import (
    DEFAULT_SCRYPT_N,
    DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R,
    Secret,
    derive_passphrase_keys,
    derive_raw_mac_key,
    validate_xts_key,
)


MAGIC = b"XTSKRY02"
VERSION = 2
PRELUDE = struct.Struct(">8sBI")
HMAC_SIZE = 32
MAX_HEADER_SIZE = 64 * 1024
DEFAULT_SECTOR_SIZE = 4096
MIN_SECTOR_SIZE = 512
MAX_SECTOR_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True)
class OperationStats:
    input_path: Path
    output_path: Path
    archived_bytes: int
    sector_size: int


@dataclass(frozen=True)
class ContainerInfo:
    path: Path
    header: dict[str, Any]
    prelude: bytes
    header_bytes: bytes
    ciphertext_offset: int
    ciphertext_size: int


def default_encrypt_output(input_path: Path) -> Path:
    return input_path.with_name(f"{input_path.name}.xts.aes")


def default_decrypt_output(input_path: Path) -> Path:
    name = input_path.name
    if name.endswith(".xts.aes"):
        name = name[: -len(".xts.aes")]
    elif name.endswith(".aes"):
        name = name[: -len(".aes")]
    return input_path.with_name(f"{name}_decrypted")


def validate_sector_size(sector_size: int) -> None:
    if sector_size < MIN_SECTOR_SIZE:
        raise ValueError(f"sector size must be at least {MIN_SECTOR_SIZE} bytes")
    if sector_size > MAX_SECTOR_SIZE:
        raise ValueError(f"sector size must be at most {MAX_SECTOR_SIZE} bytes")
    if sector_size % 16:
        raise ValueError("sector size must be a multiple of 16 bytes")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, TypeError) as exc:
        raise ArchiveFormatError(f"invalid base64 value for {field}") from exc


def _sector_tweak(base_tweak: bytes, sector_index: int) -> bytes:
    tweak_value = int.from_bytes(base_tweak, "little")
    tweak_value = (tweak_value + sector_index) % (1 << 128)
    return tweak_value.to_bytes(16, "little")


def _crypt_sector(data: bytes, key: bytes, tweak: bytes, *, decrypt: bool) -> bytes:
    if len(data) < 16:
        raise ArchiveFormatError("XTS sector is smaller than one AES block")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    return context.update(data) + context.finalize()


def _transform_stream(
    source: BinaryIO,
    target: BinaryIO,
    *,
    key: bytes,
    base_tweak: bytes,
    sector_size: int,
    decrypt: bool,
    byte_count: int,
    signer: hmac.HMAC | None = None,
) -> int:
    total = 0
    sector_index = 0
    while total < byte_count:
        chunk_size = min(sector_size, byte_count - total)
        chunk = source.read(chunk_size)
        if len(chunk) != chunk_size:
            raise ArchiveFormatError("encrypted archive ended unexpectedly")
        tweak = _sector_tweak(base_tweak, sector_index)
        transformed = _crypt_sector(chunk, key, tweak, decrypt=decrypt)
        if signer is not None and not decrypt:
            signer.update(transformed)
        target.write(transformed)
        total += len(chunk)
        sector_index += 1
    return total


class _XtsEncryptingWriter:
    """File-like writer that encrypts TAR stream bytes sector by sector."""

    def __init__(
        self,
        target: BinaryIO,
        *,
        key: bytes,
        base_tweak: bytes,
        sector_size: int,
        signer: hmac.HMAC,
    ) -> None:
        self._target = target
        self._key = key
        self._base_tweak = base_tweak
        self._sector_size = sector_size
        self._signer = signer
        self._buffer = bytearray()
        self._sector_index = 0
        self._closed = False
        self.archived_bytes = 0

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("cannot write to finalized encryption stream")
        if not data:
            return 0

        self._buffer.extend(data)
        self.archived_bytes += len(data)
        while len(self._buffer) >= self._sector_size:
            sector = bytes(self._buffer[: self._sector_size])
            del self._buffer[: self._sector_size]
            self._write_sector(sector)
        return len(data)

    def flush(self) -> None:
        self._target.flush()

    def finalize(self) -> int:
        if self._closed:
            return self.archived_bytes
        if self._buffer:
            if len(self._buffer) < 16:
                raise ArchiveFormatError(
                    "final XTS sector is smaller than one AES block"
                )
            self._write_sector(bytes(self._buffer))
            self._buffer.clear()
        self._closed = True
        return self.archived_bytes

    def _write_sector(self, sector: bytes) -> None:
        tweak = _sector_tweak(self._base_tweak, self._sector_index)
        ciphertext = _crypt_sector(sector, self._key, tweak, decrypt=False)
        self._signer.update(ciphertext)
        self._target.write(ciphertext)
        self._sector_index += 1


def _make_signer(mac_key: bytes, prelude: bytes, header_bytes: bytes) -> hmac.HMAC:
    signer = hmac.HMAC(mac_key, hashes.SHA256())
    signer.update(prelude)
    signer.update(header_bytes)
    return signer


def _derive_keys(secret: Secret, header: dict[str, Any]) -> tuple[bytes, bytes]:
    key_source = header.get("key_source")
    if secret.kind != key_source:
        raise AuthenticationError("secret type does not match archive metadata")

    if secret.kind == "passphrase":
        kdf = header.get("kdf")
        if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
            raise ArchiveFormatError("unsupported or missing passphrase KDF")
        salt = _unb64(kdf.get("salt", ""), "kdf.salt")
        try:
            return derive_passphrase_keys(
                secret.value,
                salt=salt,
                n=int(kdf["n"]),
                r=int(kdf["r"]),
                p=int(kdf["p"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ArchiveFormatError(
                "archive metadata has invalid scrypt parameters"
            ) from exc

    if secret.kind == "raw":
        validate_xts_key(secret.value)
        raw_key = secret.value
        mac_salt = _unb64(header.get("mac_salt", ""), "mac_salt")
        return raw_key, derive_raw_mac_key(raw_key, salt=mac_salt)

    raise AuthenticationError("unsupported secret type")


def _build_header(
    *,
    secret: Secret,
    sector_size: int,
    base_tweak: bytes,
    scrypt_n: int,
    scrypt_r: int,
    scrypt_p: int,
) -> tuple[dict[str, Any], bytes, bytes]:
    header: dict[str, Any] = {
        "format": "xtskryptor",
        "version": VERSION,
        "cipher": "AES-XTS",
        "auth": "HMAC-SHA256",
        "sector_size": sector_size,
        "base_tweak": _b64(base_tweak),
        "key_source": secret.kind,
    }

    if secret.kind == "passphrase":
        salt = os.urandom(16)
        xts_key, mac_key = derive_passphrase_keys(
            secret.value,
            salt=salt,
            n=scrypt_n,
            r=scrypt_r,
            p=scrypt_p,
        )
        header["kdf"] = {
            "name": "scrypt",
            "salt": _b64(salt),
            "n": scrypt_n,
            "r": scrypt_r,
            "p": scrypt_p,
        }
        return header, xts_key, mac_key

    if secret.kind == "raw":
        mac_salt = os.urandom(16)
        header["kdf"] = {"name": "none"}
        header["mac_salt"] = _b64(mac_salt)
        return header, secret.value, derive_raw_mac_key(secret.value, salt=mac_salt)

    raise ValueError("unsupported secret type")


def _encode_header(header: dict[str, Any]) -> tuple[bytes, bytes]:
    header_bytes = json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(header_bytes) > MAX_HEADER_SIZE:
        raise ValueError("archive metadata header is too large")
    prelude = PRELUDE.pack(MAGIC, VERSION, len(header_bytes))
    return prelude, header_bytes


def _read_exact(source: BinaryIO, count: int) -> bytes:
    data = source.read(count)
    if len(data) != count:
        raise ArchiveFormatError("encrypted archive ended unexpectedly")
    return data


def read_container_info(path: Path) -> ContainerInfo:
    """Read archive metadata without decrypting payload data."""

    file_size = path.stat().st_size
    minimum_size = PRELUDE.size + HMAC_SIZE
    if file_size < minimum_size:
        raise ArchiveFormatError("encrypted archive is too short")

    with path.open("rb") as source:
        prelude = _read_exact(source, PRELUDE.size)
        magic, version, header_size = PRELUDE.unpack(prelude)
        if magic != MAGIC:
            raise ArchiveFormatError("input is not an xtskryptor v2 archive")
        if version != VERSION:
            raise ArchiveFormatError(f"unsupported archive version: {version}")
        if header_size < 2 or header_size > MAX_HEADER_SIZE:
            raise ArchiveFormatError("invalid archive metadata header size")

        header_bytes = _read_exact(source, header_size)
        try:
            header = json.loads(header_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArchiveFormatError("archive metadata is not valid JSON") from exc
        if not isinstance(header, dict):
            raise ArchiveFormatError("archive metadata must be a JSON object")

    ciphertext_offset = PRELUDE.size + len(header_bytes)
    ciphertext_size = file_size - ciphertext_offset - HMAC_SIZE
    if ciphertext_size < 16:
        raise ArchiveFormatError("encrypted archive payload is too small")
    return ContainerInfo(
        path,
        header,
        prelude,
        header_bytes,
        ciphertext_offset,
        ciphertext_size,
    )


def _validate_container_info(info: ContainerInfo) -> tuple[int, bytes]:
    header = info.header
    if header.get("format") != "xtskryptor":
        raise ArchiveFormatError("archive metadata has unsupported format")
    if header.get("version") != VERSION:
        raise ArchiveFormatError("archive metadata has unsupported version")
    if header.get("cipher") != "AES-XTS" or header.get("auth") != "HMAC-SHA256":
        raise ArchiveFormatError("archive uses unsupported cryptographic settings")

    try:
        sector_size = int(header["sector_size"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ArchiveFormatError("archive metadata is missing sector size") from exc

    validate_sector_size(sector_size)

    base_tweak = _unb64(header.get("base_tweak", ""), "base_tweak")
    if len(base_tweak) != 16:
        raise ArchiveFormatError("archive base tweak must be 16 bytes")

    return sector_size, base_tweak


def _verify_hmac(info: ContainerInfo, mac_key: bytes) -> None:
    signer = _make_signer(mac_key, info.prelude, info.header_bytes)
    with info.path.open("rb") as source:
        source.seek(info.ciphertext_offset)
        remaining = info.ciphertext_size
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ArchiveFormatError("encrypted archive ended unexpectedly")
            signer.update(chunk)
            remaining -= len(chunk)
        tag = _read_exact(source, HMAC_SIZE)

    try:
        signer.verify(tag)
    except InvalidSignature as exc:
        raise AuthenticationError(
            "HMAC verification failed; the secret is wrong or the archive is corrupted"
        ) from exc


def _fsync_file(handle: BinaryIO) -> None:
    handle.flush()
    os.fsync(handle.fileno())


def _write_encrypted_file(
    input_path: Path,
    output_path: Path,
    *,
    secret: Secret,
    sector_size: int,
    overwrite: bool,
    scrypt_n: int,
    scrypt_r: int,
    scrypt_p: int,
) -> OperationStats:
    base_tweak = os.urandom(16)
    header, xts_key, mac_key = _build_header(
        secret=secret,
        sector_size=sector_size,
        base_tweak=base_tweak,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
    )
    prelude, header_bytes = _encode_header(header)
    signer = _make_signer(mac_key, prelude, header_bytes)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing file: {output_path}")

    temp_name = f".{output_path.name}.{secrets.token_hex(8)}.tmp"
    temp_output = output_path.with_name(temp_name)
    archived_bytes = 0
    try:
        with temp_output.open("xb") as target:
            target.write(prelude)
            target.write(header_bytes)
            encrypted_writer = _XtsEncryptingWriter(
                target,
                key=xts_key,
                base_tweak=base_tweak,
                sector_size=sector_size,
                signer=signer,
            )
            with tarfile.open(fileobj=encrypted_writer, mode="w|") as archive:
                add_path_to_tar(archive, input_path)
            archived_bytes = encrypted_writer.finalize()
            target.write(signer.finalize())
            _fsync_file(target)

        if output_path.exists() and not overwrite:
            raise FileExistsError(f"refusing to overwrite existing file: {output_path}")
        os.replace(temp_output, output_path)
    except Exception:
        temp_output.unlink(missing_ok=True)
        raise

    return OperationStats(input_path, output_path, archived_bytes, sector_size)


def encrypt_path(
    input_path: Path,
    output_path: Path,
    *,
    secret: Secret,
    sector_size: int = DEFAULT_SECTOR_SIZE,
    overwrite: bool = False,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> OperationStats:
    """Archive and encrypt a file or directory."""

    input_path = input_path.expanduser()
    output_path = output_path.expanduser()
    if not input_path.exists():
        raise FileNotFoundError(f"input path not found: {input_path}")
    validate_sector_size(sector_size)
    validate_encrypt_paths(input_path, output_path)

    return _write_encrypted_file(
        input_path,
        output_path,
        secret=secret,
        sector_size=sector_size,
        overwrite=overwrite,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
    )


def decrypt_archive(
    input_path: Path,
    output_dir: Path,
    *,
    secret: Secret,
    overwrite: bool = False,
) -> OperationStats:
    """Verify, decrypt, and extract an xtskryptor archive."""

    input_path = input_path.expanduser()
    output_dir = output_dir.expanduser()
    if not input_path.is_file():
        raise FileNotFoundError(f"encrypted archive not found: {input_path}")

    info = read_container_info(input_path)
    sector_size, base_tweak = _validate_container_info(info)
    xts_key, mac_key = _derive_keys(secret, info.header)
    _verify_hmac(info, mac_key)

    with tempfile.NamedTemporaryFile(
        prefix="xtskryptor-",
        suffix=".tar",
    ) as temp_archive:
        with input_path.open("rb") as source:
            source.seek(info.ciphertext_offset)
            _transform_stream(
                source,
                temp_archive,
                key=xts_key,
                base_tweak=base_tweak,
                sector_size=sector_size,
                decrypt=True,
                byte_count=info.ciphertext_size,
            )
            _fsync_file(temp_archive)
        temp_archive.seek(0)
        extract_tar_archive(Path(temp_archive.name), output_dir, overwrite=overwrite)

    return OperationStats(input_path, output_dir, info.ciphertext_size, sector_size)
