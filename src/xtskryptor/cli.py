"""Command line interface for xtskryptor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from getpass import getpass
from pathlib import Path

from . import __version__
from .crypto import (
    DEFAULT_SECTOR_SIZE,
    default_decrypt_output,
    default_encrypt_output,
    decrypt_archive,
    encrypt_path,
    read_container_info,
)
from .exceptions import XtsKryptorError
from .secrets import (
    DEFAULT_SCRYPT_N,
    DEFAULT_SCRYPT_P,
    DEFAULT_SCRYPT_R,
    Secret,
    raw_key_from_hex,
)


PASSPHRASE_ENV = "XTSKRYPTOR_PASSPHRASE"
RAW_KEY_ENV = "XTSKRYPTOR_RAW_KEY_HEX"


def _read_text_secret(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    return value.rstrip("\r\n")


def _load_secret(args: argparse.Namespace, *, confirm: bool) -> Secret:
    if args.raw_key_hex:
        return Secret.from_raw_key(raw_key_from_hex(args.raw_key_hex))
    if args.raw_key_file:
        return Secret.from_raw_key(args.raw_key_file.read_bytes())
    if os.environ.get(RAW_KEY_ENV):
        return Secret.from_raw_key(raw_key_from_hex(os.environ[RAW_KEY_ENV]))

    if args.passphrase_file:
        return Secret.from_passphrase(_read_text_secret(args.passphrase_file))
    if os.environ.get(PASSPHRASE_ENV):
        return Secret.from_passphrase(os.environ[PASSPHRASE_ENV])

    passphrase = getpass("Passphrase: ")
    if confirm and not args.no_confirm:
        repeated = getpass("Confirm passphrase: ")
        if passphrase != repeated:
            raise ValueError("passphrases do not match")
    return Secret.from_passphrase(passphrase)


def _add_secret_arguments(parser: argparse.ArgumentParser) -> None:
    secret_group = parser.add_mutually_exclusive_group()
    secret_group.add_argument(
        "--passphrase-file",
        type=Path,
        help=(
            "Read the passphrase from a UTF-8 text file with one optional "
            "trailing newline."
        ),
    )
    secret_group.add_argument(
        "--raw-key-hex",
        help="Use a raw AES-XTS key encoded as 64 or 128 hexadecimal characters.",
    )
    secret_group.add_argument(
        "--raw-key-file",
        type=Path,
        help="Read a raw 32-byte or 64-byte AES-XTS key from a binary file.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xtskryptor",
        description=(
            "Encrypt and decrypt files or folders as authenticated AES-XTS "
            "archives."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt a file or folder.",
    )
    encrypt_parser.add_argument(
        "input_path",
        type=Path,
        help="File or folder to encrypt.",
    )
    encrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Encrypted output path. Default: INPUT.xts.aes",
    )
    encrypt_parser.add_argument(
        "--sector-size",
        type=int,
        default=DEFAULT_SECTOR_SIZE,
        help=f"XTS sector size in bytes. Default: {DEFAULT_SECTOR_SIZE}.",
    )
    encrypt_parser.add_argument(
        "--scrypt-n",
        type=int,
        default=DEFAULT_SCRYPT_N,
        help=f"Scrypt CPU/memory cost parameter. Default: {DEFAULT_SCRYPT_N}.",
    )
    encrypt_parser.add_argument(
        "--scrypt-r",
        type=int,
        default=DEFAULT_SCRYPT_R,
        help=f"Scrypt block size parameter. Default: {DEFAULT_SCRYPT_R}.",
    )
    encrypt_parser.add_argument(
        "--scrypt-p",
        type=int,
        default=DEFAULT_SCRYPT_P,
        help=f"Scrypt parallelization parameter. Default: {DEFAULT_SCRYPT_P}.",
    )
    encrypt_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite the encrypted output file if it already exists.",
    )
    encrypt_parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Do not ask for passphrase confirmation when prompting interactively.",
    )
    _add_secret_arguments(encrypt_parser)

    decrypt_parser = subparsers.add_parser(
        "decrypt",
        help="Decrypt and extract an archive.",
    )
    decrypt_parser.add_argument("input_path", type=Path, help="Encrypted archive path.")
    decrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Directory to extract into. Default: encrypted-name_decrypted",
    )
    decrypt_parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Allow extraction over existing target paths.",
    )
    decrypt_parser.set_defaults(no_confirm=True)
    _add_secret_arguments(decrypt_parser)

    info_parser = subparsers.add_parser(
        "info",
        help="Show archive metadata without decrypting payload data.",
    )
    info_parser.add_argument("input_path", type=Path, help="Encrypted archive path.")
    info_parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw metadata as JSON.",
    )
    return parser


def _print_info(path: Path, *, as_json: bool) -> None:
    info = read_container_info(path)
    if as_json:
        print(json.dumps(info.header, indent=2, sort_keys=True))
        return

    header = info.header
    print(f"Path: {path}")
    print(f"Format: {header.get('format')} v{header.get('version')}")
    print(f"Cipher: {header.get('cipher')}")
    print(f"Authentication: {header.get('auth')}")
    print(f"Key source: {header.get('key_source')}")
    print(f"Sector size: {header.get('sector_size')} bytes")
    print(f"Archived bytes: {info.ciphertext_size}")
    kdf = header.get("kdf", {})
    if isinstance(kdf, dict) and kdf.get("name") == "scrypt":
        print(f"KDF: scrypt n={kdf.get('n')} r={kdf.get('r')} p={kdf.get('p')}")
    elif isinstance(kdf, dict):
        print(f"KDF: {kdf.get('name')}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "info":
            _print_info(args.input_path, as_json=args.json)
            return 0

        if args.command == "encrypt":
            secret = _load_secret(args, confirm=True)
            output_path = args.output or default_encrypt_output(args.input_path)
            stats = encrypt_path(
                args.input_path,
                output_path,
                secret=secret,
                sector_size=args.sector_size,
                overwrite=args.force,
                scrypt_n=args.scrypt_n,
                scrypt_r=args.scrypt_r,
                scrypt_p=args.scrypt_p,
            )
            print(
                f"Encrypted {args.input_path} into {output_path} "
                f"({stats.archived_bytes} archived bytes)."
            )
            return 0

        secret = _load_secret(args, confirm=False)
        output_dir = args.output or default_decrypt_output(args.input_path)
        stats = decrypt_archive(
            args.input_path,
            output_dir,
            secret=secret,
            overwrite=args.force,
        )
        print(
            f"Decrypted {args.input_path} into {output_dir} "
            f"({stats.archived_bytes} archived bytes)."
        )
        return 0
    except (OSError, ValueError, XtsKryptorError) as exc:
        print(f"xtskryptor: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
