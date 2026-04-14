# Contributing

## Development Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests
```

## Project Rules

- Keep the archive format versioned and backwards-compatible unless a breaking
  change is explicitly documented.
- Do not add unauthenticated encryption paths.
- Do not accept unsafe TAR extraction behavior. Archive members must be
  validated before extraction.
- Add tests for encryption format changes, path handling, and authentication
  failures.

## Release Checklist

- Run `python3 -m unittest discover -s tests`.
- Run a manual encrypt/decrypt cycle on a file and a directory.
- Update `README.md` if CLI behavior or archive format metadata changes.
- Tag the release after the package version has been updated.
