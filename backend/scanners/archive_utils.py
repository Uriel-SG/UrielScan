"""Shared streaming download and Zip-Slip/Tar-Slip-safe archive extraction helpers for engine provisioning."""

import os
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

import httpx


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_root = dest_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.infolist():
            target = (dest_root / member.filename).resolve()
            if not (target == dest_root or str(target).startswith(str(dest_root) + os.sep)):
                raise ValueError(f"Unsafe ZIP path blocked: {member.filename}")
        zf.extractall(dest_root)


def safe_extract_tar(tar_path: Path, dest_dir: Path) -> None:
    dest_root = dest_dir.resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                # Validate symlink/hardlink targets remain safe
                link_target = (dest_root / member.linkname).resolve()
                if not (link_target == dest_root or str(link_target).startswith(str(dest_root) + os.sep)):
                    raise ValueError(f"Unsafe TAR link target blocked: {member.linkname}")
            target = (dest_root / member.name).resolve()
            if not (target == dest_root or str(target).startswith(str(dest_root) + os.sep)):
                raise ValueError(f"Unsafe TAR path blocked: {member.name}")
        tf.extractall(dest_root)


async def stream_download(
    url: str,
    dest_path: Path,
    timeout: float = 180.0,
    user_agent: str = "UrielScan-Installer/1.0",
) -> None:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=20.0), follow_redirects=True) as client:
        async with client.stream("GET", url, headers={"User-Agent": user_agent}) as resp:
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code} downloading {url}")
            with open(dest_path, "wb") as fh:
                async for chunk in resp.aiter_bytes(chunk_size=131072):
                    if chunk:
                        fh.write(chunk)
