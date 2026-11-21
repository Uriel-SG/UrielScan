"""SecLists preset downloader and custom .txt wordlist manager for Web Recon & Subdomain Enumeration."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.scanners.archive_utils import stream_download

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PRESET_WORDLISTS_DIR = BASE_DIR / "bin" / "wordlists"
CUSTOM_WORDLISTS_DIR = BASE_DIR / "data" / "wordlists"

MAX_CUSTOM_WORDLIST_BYTES = 25 * 1024 * 1024  # 25 MB
_VALID_CATEGORIES = ("dns", "web")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.txt$")

SECLISTS_PRESETS: Dict[str, List[Dict[str, str]]] = {
    "dns": [
        {
            "id": "n0kovo",
            "name": "n0kovo_subdomains.txt (SecLists)",
            "filename": "n0kovo_subdomains.txt",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/n0kovo_subdomains.txt",
            "description": "Large modern DNS subdomain corpus (~19 MB, default).",
        },
        {
            "id": "top1m_110k",
            "name": "subdomains-top1million-110000.txt (SecLists)",
            "filename": "subdomains-top1million-110000.txt",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
            "description": "Balanced top 110k subdomain prefixes.",
        },
        {
            "id": "italian",
            "name": "italian-subdomains.txt (SecLists)",
            "filename": "italian-subdomains.txt",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/italian-subdomains.txt",
            "description": "Compact Italian-oriented subdomain list (~74 KB).",
        },
    ],
    "web": [
        {
            "id": "dirbuster_medium",
            "name": "DirBuster 2.3 Medium (SecLists)",
            "filename": "DirBuster-2007_directory-list-2.3-medium.txt",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
            "description": "Standard DirBuster medium directory list (~220k entries, default).",
        },
        {
            "id": "dirbuster_big",
            "name": "DirBuster 2.3 Big (SecLists)",
            "filename": "DirBuster-2007_directory-list-2.3-big.txt",
            "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
            "description": "Comprehensive DirBuster big directory list (~1.2M entries).",
        },
    ],
}


def _validate_category(category: str) -> str:
    cat = (category or "").strip().lower()
    if cat not in _VALID_CATEGORIES:
        raise ValueError(f"Invalid wordlist category '{category}'. Expected 'dns' or 'web'.")
    return cat


def sanitize_wordlist_filename(filename: str) -> str:
    raw_name = Path((filename or "").replace("\\", "/")).name.strip()
    if not raw_name.lower().endswith(".txt"):
        raw_name = f"{raw_name}.txt" if raw_name else ""
    if not _SAFE_FILENAME_RE.match(raw_name):
        raise ValueError(
            "Invalid filename. Use only letters, digits, dots, underscores, hyphens and .txt extension."
        )
    return raw_name


def _count_nonempty_lines(path: Path) -> Optional[int]:
    try:
        count = 0
        with open(path, "rb") as fh:
            for line in fh:
                if line.strip() and not line.lstrip().startswith(b"#"):
                    count += 1
        return count
    except Exception:
        return None


def list_wordlists() -> Dict[str, List[Dict[str, Any]]]:
    """Return available SecLists presets and user-uploaded custom wordlists grouped by category."""
    result: Dict[str, List[Dict[str, Any]]] = {"dns": [], "web": []}
    for cat in _VALID_CATEGORIES:
        for preset in SECLISTS_PRESETS[cat]:
            cached_path = PRESET_WORDLISTS_DIR / cat / preset["filename"]
            is_cached = cached_path.is_file()
            result[cat].append({
                "id": preset["id"],
                "name": preset["name"],
                "filename": preset["filename"],
                "category": cat,
                "source": "seclists",
                "cached": is_cached,
                "size_bytes": cached_path.stat().st_size if is_cached else None,
                "description": preset["description"],
            })

        custom_dir = CUSTOM_WORDLISTS_DIR / cat
        if custom_dir.is_dir():
            for fp in sorted(custom_dir.glob("*.txt")):
                if not fp.is_file():
                    continue
                result[cat].append({
                    "id": f"custom:{fp.name}",
                    "name": f"{fp.name} (Custom)",
                    "filename": fp.name,
                    "category": cat,
                    "source": "custom",
                    "cached": True,
                    "size_bytes": fp.stat().st_size,
                    "lines": _count_nonempty_lines(fp),
                    "description": "User-uploaded custom wordlist.",
                })
    return result


def save_custom_wordlist(category: str, filename: str, content: bytes) -> Dict[str, Any]:
    """Validate and store a custom .txt wordlist under data/wordlists/<category>/."""
    cat = _validate_category(category)
    safe_name = sanitize_wordlist_filename(filename)

    if not content:
        raise ValueError("Uploaded wordlist file is empty.")
    if len(content) > MAX_CUSTOM_WORDLIST_BYTES:
        raise ValueError("Wordlist exceeds maximum allowed size (25 MB).")
    if b"\x00" in content:
        raise ValueError("Binary content detected; only UTF-8 plain text .txt wordlists are allowed.")

    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Wordlist must be valid UTF-8 text.") from exc

    non_empty = sum(1 for ln in decoded.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
    if non_empty == 0:
        raise ValueError("Wordlist contains zero usable entries.")

    dest_dir = (CUSTOM_WORDLISTS_DIR / cat).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = (dest_dir / safe_name).resolve()
    if dest_path.parent != dest_dir:
        raise ValueError("Path traversal rejected.")

    dest_path.write_text(decoded, encoding="utf-8")
    return {
        "id": f"custom:{safe_name}",
        "name": f"{safe_name} (Custom)",
        "filename": safe_name,
        "category": cat,
        "source": "custom",
        "cached": True,
        "size_bytes": dest_path.stat().st_size,
        "lines": non_empty,
        "description": "User-uploaded custom wordlist.",
    }


def delete_custom_wordlist(category: str, filename: str) -> bool:
    """Remove a user-uploaded custom wordlist safely."""
    cat = _validate_category(category)
    safe_name = sanitize_wordlist_filename(filename)
    dest_dir = (CUSTOM_WORDLISTS_DIR / cat).resolve()
    target = (dest_dir / safe_name).resolve()
    if target.parent != dest_dir or not target.is_file():
        return False
    target.unlink()
    return True


async def resolve_wordlist_path(category: str, wordlist_id: Optional[str]) -> Optional[Path]:
    """Resolve a SecLists preset (downloading on demand) or custom wordlist path."""
    cat = _validate_category(category)
    if not wordlist_id or wordlist_id == "passive_only":
        return None

    wid = str(wordlist_id).strip()
    if wid.startswith("custom:"):
        safe_name = sanitize_wordlist_filename(wid[len("custom:"):])
        cpath = (CUSTOM_WORDLISTS_DIR / cat / safe_name).resolve()
        if cpath.parent != (CUSTOM_WORDLISTS_DIR / cat).resolve() or not cpath.is_file():
            raise FileNotFoundError(f"Custom wordlist not found: {safe_name}")
        return cpath

    # Check if caller passed bare custom filename
    if _SAFE_FILENAME_RE.match(wid):
        cpath = (CUSTOM_WORDLISTS_DIR / cat / wid).resolve()
        if cpath.is_file():
            return cpath

    preset = next((p for p in SECLISTS_PRESETS[cat] if p["id"] == wid), None)
    if not preset:
        preset = SECLISTS_PRESETS[cat][0]

    dest_dir = (PRESET_WORDLISTS_DIR / cat).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = (dest_dir / preset["filename"]).resolve()
    if dest_path.is_file() and dest_path.stat().st_size > 0:
        return dest_path

    tmp_path = dest_dir / f".{preset['filename']}.downloading"
    try:
        await stream_download(preset["url"], tmp_path, timeout=180.0, user_agent="UrielScan-SecLists/1.0")
        tmp_path.replace(dest_path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return dest_path
