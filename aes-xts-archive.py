#!/usr/bin/env python3
"""Compatibility entry point for the xtskryptor command line interface."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if SRC.is_dir():
    sys.path.insert(0, str(SRC))

from xtskryptor.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
