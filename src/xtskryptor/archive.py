"""TAR archive creation and safe extraction helpers."""

from __future__ import annotations

import tarfile
from pathlib import Path


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_encrypt_paths(input_path: Path, output_path: Path) -> None:
    input_root = input_path.resolve()
    output_target = output_path.resolve(strict=False)

    if output_target == input_root:
        raise ValueError("encrypted output path must be different from input path")

    if input_path.is_dir() and is_relative_to(output_target, input_root):
        raise ValueError("encrypted output path must be outside the input folder")


def _tar_filter(member: tarfile.TarInfo) -> tarfile.TarInfo:
    if member.isfile() or member.isdir() or member.issym() or member.islnk():
        return member
    raise ValueError(f"unsupported source file type in archive: {member.name}")


def add_path_to_tar(archive: tarfile.TarFile, input_path: Path) -> None:
    arcname = input_path.resolve().name or input_path.name
    if not arcname:
        raise ValueError("input path must have a usable name")
    archive.add(input_path, arcname=arcname, recursive=True, filter=_tar_filter)


def create_tar_archive(input_path: Path, archive_path: Path) -> int:
    """Create an uncompressed TAR archive and return its byte size."""

    with tarfile.open(archive_path, mode="w") as archive:
        add_path_to_tar(archive, input_path)
    return archive_path.stat().st_size


def validate_archive_member(member: tarfile.TarInfo, output_dir: Path) -> Path:
    member_path = Path(member.name)
    if member_path.is_absolute():
        raise ValueError(f"archive member uses an absolute path: {member.name}")
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ValueError(f"archive member has unsupported type: {member.name}")

    output_root = output_dir.resolve()
    target_path = (output_root / member_path).resolve(strict=False)
    if not is_relative_to(target_path, output_root):
        raise ValueError(f"archive member escapes output directory: {member.name}")

    if member.issym() or member.islnk():
        link_path = Path(member.linkname)
        if link_path.is_absolute():
            raise ValueError(f"archive link uses an absolute target: {member.name}")
        link_target = (target_path.parent / link_path).resolve(strict=False)
        if not is_relative_to(link_target, output_root):
            raise ValueError(f"archive link escapes output directory: {member.name}")

    return target_path


def extract_tar_archive(
    archive_path: Path,
    output_dir: Path,
    *,
    overwrite: bool,
) -> None:
    """Extract a TAR archive after validating paths and link targets."""

    output_dir.mkdir(parents=True, exist_ok=True)
    output_root = output_dir.resolve()

    with tarfile.open(archive_path, mode="r:*") as archive:
        members = archive.getmembers()
        target_paths = [
            validate_archive_member(member, output_root)
            for member in members
        ]

        if not overwrite:
            existing_targets = [target for target in target_paths if target.exists()]
            if existing_targets:
                first = existing_targets[0]
                raise FileExistsError(
                    f"refusing to overwrite existing extraction target: {first}"
                )

        try:
            archive.extractall(output_root, members=members, filter="data")
        except TypeError:
            archive.extractall(output_root, members=members)
