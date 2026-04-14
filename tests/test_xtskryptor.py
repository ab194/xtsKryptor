from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from xtskryptor.cli import main
from xtskryptor.crypto import decrypt_archive, encrypt_path, read_container_info
from xtskryptor.exceptions import AuthenticationError
from xtskryptor.secrets import Secret


TEST_SCRYPT_N = 2**12
PASSPHRASE = "correct horse battery staple"


class XtsKryptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_source_tree(self) -> Path:
        source = self.root / "source"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (source / "hello.txt").write_text("hello xtskryptor\n", encoding="utf-8")
        (nested / "data.bin").write_bytes(bytes(range(256)) * 4)
        return source

    def test_directory_roundtrip_with_passphrase(self) -> None:
        source = self.make_source_tree()
        archive = self.root / "source.xts.aes"
        restored = self.root / "restored"

        encrypt_path(
            source,
            archive,
            secret=Secret.from_passphrase(PASSPHRASE),
            scrypt_n=TEST_SCRYPT_N,
        )
        self.assertTrue(archive.is_file())
        self.assertNotIn(b"hello xtskryptor", archive.read_bytes())

        decrypt_archive(
            archive,
            restored,
            secret=Secret.from_passphrase(PASSPHRASE),
        )

        self.assertEqual(
            (restored / "source" / "hello.txt").read_text(encoding="utf-8"),
            "hello xtskryptor\n",
        )
        self.assertEqual(
            (restored / "source" / "nested" / "data.bin").read_bytes(),
            bytes(range(256)) * 4,
        )

    def test_single_file_roundtrip_with_raw_key(self) -> None:
        source = self.root / "note.txt"
        source.write_text("raw key path\n", encoding="utf-8")
        archive = self.root / "note.xts.aes"
        restored = self.root / "out"
        key = b"a" * 32 + b"b" * 32

        encrypt_path(source, archive, secret=Secret.from_raw_key(key))
        decrypt_archive(archive, restored, secret=Secret.from_raw_key(key))

        self.assertEqual(
            (restored / "note.txt").read_text(encoding="utf-8"),
            "raw key path\n",
        )

    def test_wrong_passphrase_fails_before_extraction(self) -> None:
        source = self.make_source_tree()
        archive = self.root / "source.xts.aes"
        restored = self.root / "restored"

        encrypt_path(
            source,
            archive,
            secret=Secret.from_passphrase(PASSPHRASE),
            scrypt_n=TEST_SCRYPT_N,
        )

        with self.assertRaises(AuthenticationError):
            decrypt_archive(
                archive,
                restored,
                secret=Secret.from_passphrase("wrong passphrase"),
            )
        self.assertFalse((restored / "source").exists())

    def test_corrupted_ciphertext_is_rejected(self) -> None:
        source = self.make_source_tree()
        archive = self.root / "source.xts.aes"
        encrypt_path(
            source,
            archive,
            secret=Secret.from_passphrase(PASSPHRASE),
            scrypt_n=TEST_SCRYPT_N,
        )

        data = bytearray(archive.read_bytes())
        data[-40] ^= 0x01
        archive.write_bytes(data)

        with self.assertRaises(AuthenticationError):
            decrypt_archive(
                archive,
                self.root / "restored",
                secret=Secret.from_passphrase(PASSPHRASE),
            )

    def test_encrypt_rejects_output_inside_input_directory(self) -> None:
        source = self.make_source_tree()
        with self.assertRaises(ValueError):
            encrypt_path(
                source,
                source / "nested" / "archive.xts.aes",
                secret=Secret.from_passphrase(PASSPHRASE),
                scrypt_n=TEST_SCRYPT_N,
            )

    def test_info_reads_metadata_without_secret(self) -> None:
        source = self.make_source_tree()
        archive = self.root / "source.xts.aes"
        encrypt_path(
            source,
            archive,
            secret=Secret.from_passphrase(PASSPHRASE),
            scrypt_n=TEST_SCRYPT_N,
        )

        info = read_container_info(archive)
        self.assertEqual(info.header["format"], "xtskryptor")
        self.assertEqual(info.header["cipher"], "AES-XTS")
        self.assertEqual(info.header["auth"], "HMAC-SHA256")
        self.assertEqual(info.header["kdf"]["name"], "scrypt")
        self.assertGreater(info.ciphertext_size, 0)

    def test_cli_roundtrip_uses_environment_passphrase(self) -> None:
        source = self.root / "cli.txt"
        source.write_text("cli roundtrip\n", encoding="utf-8")
        archive = self.root / "cli.xts.aes"
        restored = self.root / "cli-restored"

        stdout = io.StringIO()
        with (
            patch.dict(os.environ, {"XTSKRYPTOR_PASSPHRASE": PASSPHRASE}),
            redirect_stdout(stdout),
        ):
            self.assertEqual(
                main(
                    [
                        "encrypt",
                        str(source),
                        "--output",
                        str(archive),
                        "--scrypt-n",
                        str(TEST_SCRYPT_N),
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "decrypt",
                        str(archive),
                        "--output",
                        str(restored),
                    ]
                ),
                0,
            )

        self.assertEqual(
            (restored / "cli.txt").read_text(encoding="utf-8"),
            "cli roundtrip\n",
        )


if __name__ == "__main__":
    unittest.main()
