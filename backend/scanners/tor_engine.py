"""Managed Tor Expert Bundle lifecycle, SOCKS5/HTTP proxy tunneling, and exit IP verification."""

import asyncio
import ipaddress
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import httpx

from backend.scanners.archive_utils import safe_extract_tar, stream_download

BASE_DIR = Path(__file__).resolve().parent.parent.parent
BIN_DIR = BASE_DIR / "bin"
TOR_DIR = BIN_DIR / "tor"
TOR_DATA_DIR = BASE_DIR / "data" / "tor_data"

TOR_EXPERT_BUNDLE_VERSION = "16.0.1"
DEFAULT_TOR_SOCKS_PORT = 19050
DEFAULT_TOR_CONTROL_PORT = 19051

_ALLOWED_PROXY_SCHEMES = {"socks5", "socks5h", "http", "https"}
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

_TOR_PROCESS: Optional[subprocess.Popen] = None
_TOR_LOCK = threading.Lock()
_TOR_BOOTSTRAPPED_EVENT = threading.Event()


def validate_proxy_url(proxy_url: Optional[str]) -> Optional[str]:
    """Validate and normalize an outbound proxy URL (socks5/socks5h/http/https)."""
    if not proxy_url or not str(proxy_url).strip():
        return None
    raw_str = str(proxy_url)
    if _CONTROL_CHAR_RE.search(raw_str):
        raise ValueError("Proxy URL contains invalid control characters.")
    cleaned = raw_str.strip()

    parsed = urllib.parse.urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_PROXY_SCHEMES:
        raise ValueError(
            f"Unsupported proxy scheme '{scheme}'. Allowed: socks5, socks5h, http, https."
        )
    if not parsed.hostname:
        raise ValueError("Proxy URL must include a valid host (e.g. socks5h://127.0.0.1:9050).")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid proxy port in URL: {exc}") from exc

    if port is None:
        if scheme == "http":
            port = 8080
        elif scheme == "https":
            port = 8443
        else:
            port = 1080
    if not (1 <= port <= 65535):
        raise ValueError("Proxy port must be between 1 and 65535.")

    host_fmt = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    auth = ""
    if parsed.username is not None:
        user_enc = urllib.parse.quote(urllib.parse.unquote(parsed.username), safe="")
        if parsed.password is not None:
            pass_enc = urllib.parse.quote(urllib.parse.unquote(parsed.password), safe="")
            auth = f"{user_enc}:{pass_enc}@"
        else:
            auth = f"{user_enc}@"

    return f"{scheme}://{auth}{host_fmt}:{port}"


def to_httpx_proxy_url(proxy_url: Optional[str]) -> Optional[str]:
    """Ensure socks5:// URLs are upgraded to socks5h:// for remote DNS resolution."""
    validated = validate_proxy_url(proxy_url)
    if not validated:
        return None
    if validated.lower().startswith("socks5://"):
        return "socks5h://" + validated[len("socks5://"):]
    return validated


def _tor_env(tor_bin: str) -> Dict[str, str]:
    env = os.environ.copy()
    tor_parent = str(Path(tor_bin).resolve().parent)
    sys_name = platform.system()
    if sys_name == "Linux":
        prev = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{tor_parent}{os.pathsep}{prev}" if prev else tor_parent
    elif sys_name == "Darwin":
        prev = env.get("DYLD_LIBRARY_PATH", "")
        env["DYLD_LIBRARY_PATH"] = f"{tor_parent}{os.pathsep}{prev}" if prev else tor_parent
    env["PATH"] = f"{tor_parent}{os.pathsep}{env.get('PATH', '')}"
    return env


def get_tor_bin_path() -> Optional[str]:
    """Locate the managed Tor Expert Bundle binary in bin/tor or fallback to system PATH."""
    is_win = platform.system() == "Windows"
    exe_name = "tor.exe" if is_win else "tor"

    direct_candidates = [
        TOR_DIR / "tor" / exe_name,
        TOR_DIR / exe_name,
    ]
    for cand in direct_candidates:
        if cand.is_file():
            return str(cand)

    if TOR_DIR.is_dir():
        for match in sorted(TOR_DIR.rglob(exe_name)):
            if match.is_file() and match.name == exe_name:
                return str(match)

    sys_tor = shutil.which("tor")
    if sys_tor:
        return sys_tor
    return None


def _tcp_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def is_tor_running(socks_port: int = DEFAULT_TOR_SOCKS_PORT) -> bool:
    """Return True if our managed Tor process is alive or the managed SOCKS port responds."""
    if _TOR_PROCESS is not None and _TOR_PROCESS.poll() is None:
        return _tcp_port_open("127.0.0.1", socks_port, timeout=0.5)
    return _tcp_port_open("127.0.0.1", socks_port, timeout=0.4)


def detect_tor() -> Dict[str, Any]:
    """Detect whether Tor Expert Bundle (or system Tor) is installed and whether daemon is up."""
    tpath = get_tor_bin_path()
    running = is_tor_running(DEFAULT_TOR_SOCKS_PORT)
    if not tpath:
        return {
            "installed": False,
            "version": "",
            "path": "",
            "running": running,
            "socks_port": DEFAULT_TOR_SOCKS_PORT,
            "control_port": DEFAULT_TOR_CONTROL_PORT,
            "proxy_url": f"socks5h://127.0.0.1:{DEFAULT_TOR_SOCKS_PORT}" if running else "",
        }

    version = "Available"
    try:
        proc = subprocess.run(
            [tpath, "--version"],
            env=_tor_env(tpath),
            capture_output=True,
            text=True,
            timeout=5,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        m = re.search(r"Tor\s+version\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)", out, re.IGNORECASE)
        if m:
            version = f"v{m.group(1)}"
        elif out.strip():
            version = out.splitlines()[0].strip()[:48]
    except Exception:
        pass

    return {
        "installed": True,
        "version": version,
        "path": tpath,
        "running": running,
        "socks_port": DEFAULT_TOR_SOCKS_PORT,
        "control_port": DEFAULT_TOR_CONTROL_PORT,
        "proxy_url": f"socks5h://127.0.0.1:{DEFAULT_TOR_SOCKS_PORT}",
    }


def _tor_bundle_filename(version: str) -> Tuple[str, str]:
    sys_name = platform.system().lower()
    machine = platform.machine().lower()

    if sys_name == "windows":
        target = "windows-x86_64"
    elif sys_name == "darwin":
        target = "macos-aarch64" if machine in ("arm64", "aarch64") else "macos-x86_64"
    else:
        target = "linux-aarch64" if machine in ("arm64", "aarch64") else "linux-x86_64"

    fname = f"tor-expert-bundle-{target}-{version}.tar.gz"
    return target, fname


async def _resolve_latest_tor_bundle_url() -> Tuple[str, str]:
    target, fname = _tor_bundle_filename(TOR_EXPERT_BUNDLE_VERSION)
    pinned_url = f"https://dist.torproject.org/torbrowser/{TOR_EXPERT_BUNDLE_VERSION}/{fname}"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            head = await client.head(pinned_url, headers={"User-Agent": "UrielScan-Installer/1.0"})
            if head.status_code == 200:
                return pinned_url, fname

            idx = await client.get(
                "https://dist.torproject.org/torbrowser/",
                headers={"User-Agent": "UrielScan-Installer/1.0"},
            )
            if idx.status_code == 200:
                versions = re.findall(r'href="(\d+\.\d+(?:\.\d+)?)/"', idx.text)
                if versions:
                    versions.sort(key=lambda v: [int(p) for p in v.split(".")], reverse=True)
                    latest_ver = versions[0]
                    _, latest_fname = _tor_bundle_filename(latest_ver)
                    return f"https://dist.torproject.org/torbrowser/{latest_ver}/{latest_fname}", latest_fname
    except Exception:
        pass
    return pinned_url, fname


async def install_tor() -> Dict[str, Any]:
    """Download and extract the official Tor Expert Bundle into bin/tor cleanly."""
    det = detect_tor()
    if det["installed"]:
        return {
            "success": True,
            "version": det["version"],
            "path": det["path"],
            "message": f"Tor already installed: {det['path']} ({det['version']})",
        }

    dl_url, fname = await _resolve_latest_tor_bundle_url()
    archive_path = BIN_DIR / fname
    try:
        TOR_DIR.mkdir(parents=True, exist_ok=True)
        await stream_download(dl_url, archive_path, timeout=300.0)
        safe_extract_tar(archive_path, TOR_DIR)
    except Exception as exc:
        return {
            "success": False,
            "version": "",
            "path": "",
            "message": f"Failed to install Tor Expert Bundle: {exc}",
        }
    finally:
        if archive_path.exists():
            try:
                archive_path.unlink()
            except Exception:
                pass

    if platform.system() != "Windows":
        for p in TOR_DIR.rglob("*"):
            if p.is_file() and (p.name == "tor" or p.name.startswith("lyrebird") or p.suffix == ".so"):
                try:
                    os.chmod(str(p), 0o755)
                except Exception:
                    pass

    after = detect_tor()
    if not after["installed"]:
        return {
            "success": False,
            "version": "",
            "path": "",
            "message": "Tor Expert Bundle extracted, but tor executable could not be located.",
        }

    return {
        "success": True,
        "version": after["version"],
        "path": after["path"],
        "message": f"Tor installed successfully: {after['path']} ({after['version']})",
    }


def _find_geoip_files() -> Tuple[Optional[Path], Optional[Path]]:
    geoip: Optional[Path] = None
    geoip6: Optional[Path] = None
    if TOR_DIR.is_dir():
        for cand in TOR_DIR.rglob("geoip"):
            if cand.is_file():
                geoip = cand
                break
        for cand6 in TOR_DIR.rglob("geoip6"):
            if cand6.is_file():
                geoip6 = cand6
                break
    return geoip, geoip6


def _stop_tor_sync() -> Dict[str, Any]:
    global _TOR_PROCESS
    with _TOR_LOCK:
        _TOR_BOOTSTRAPPED_EVENT.clear()
        proc = _TOR_PROCESS
        _TOR_PROCESS = None
        if proc is None or proc.poll() is not None:
            return {"ok": True, "stopped": False, "message": "Tor daemon was not running."}

        try:
            proc.terminate()
            proc.wait(timeout=4.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass
        except Exception:
            pass
        return {"ok": True, "stopped": True, "message": "Tor daemon stopped."}


async def stop_tor_daemon() -> Dict[str, Any]:
    """Stop the managed Tor daemon cleanly from any event loop."""
    return await asyncio.to_thread(_stop_tor_sync)


def _start_and_wait_tor_sync(
    tor_bin: str,
    timeout: float,
    socks_port: int,
    control_port: int,
    log: Callable[[str, str], None],
) -> Dict[str, Any]:
    global _TOR_PROCESS
    with _TOR_LOCK:
        proxy_url = f"socks5h://127.0.0.1:{socks_port}"
        if _TOR_PROCESS is not None and _TOR_PROCESS.poll() is None and _tcp_port_open("127.0.0.1", socks_port, 0.5):
            return {"ok": True, "proxy_url": proxy_url, "socks_port": socks_port, "control_port": control_port}

        if _TOR_PROCESS is not None and _TOR_PROCESS.poll() is None:
            try:
                _TOR_PROCESS.kill()
                _TOR_PROCESS.wait(timeout=2.0)
            except Exception:
                pass
        _TOR_PROCESS = None
        _TOR_BOOTSTRAPPED_EVENT.clear()

        TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
        torrc_path = TOR_DATA_DIR / "torrc"
        torrc_lines = [
            f"SocksPort 127.0.0.1:{socks_port}",
            f"ControlPort 127.0.0.1:{control_port}",
            "CookieAuthentication 1",
            f"DataDirectory {TOR_DATA_DIR}",
            "Log notice stdout",
            "CircuitBuildTimeout 20",
            "LearnCircuitBuildTimeout 0",
        ]
        geoip, geoip6 = _find_geoip_files()
        if geoip:
            torrc_lines.append(f"GeoIPFile {geoip}")
        if geoip6:
            torrc_lines.append(f"GeoIPv6File {geoip6}")

        torrc_path.write_text("\n".join(torrc_lines) + "\n", encoding="utf-8")

        log("INFO", f"[Tor] Starting Tor daemon on 127.0.0.1:{socks_port} (control {control_port})...")
        try:
            proc = subprocess.Popen(
                [tor_bin, "-f", str(torrc_path)],
                env=_tor_env(tor_bin),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception as exc:
            return {"ok": False, "error": f"Failed to start Tor process: {exc}"}

        last_lines: list[str] = []

        def _reader_thread() -> None:
            if not proc.stdout:
                return
            try:
                for raw in proc.stdout:
                    line = raw.strip()
                    if not line:
                        continue
                    last_lines.append(line)
                    if len(last_lines) > 15:
                        last_lines.pop(0)
                    if "Bootstrapped " in line and not _TOR_BOOTSTRAPPED_EVENT.is_set():
                        m = re.search(r"Bootstrapped\s+(\d+%)\s+\(([^)]+)\)", line)
                        if m:
                            log("INFO", f"[Tor] Bootstrap {m.group(1)} ({m.group(2)})")
                    if "Bootstrapped 100%" in line:
                        _TOR_BOOTSTRAPPED_EVENT.set()
            except Exception:
                pass

        t = threading.Thread(target=_reader_thread, name="UrielScanTorReader", daemon=True)
        t.start()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if _TOR_BOOTSTRAPPED_EVENT.is_set() and _tcp_port_open("127.0.0.1", socks_port, timeout=0.5):
                _TOR_PROCESS = proc
                return {
                    "ok": True,
                    "proxy_url": proxy_url,
                    "socks_port": socks_port,
                    "control_port": control_port,
                }
            if proc.poll() is not None:
                break
            time.sleep(0.35)

        try:
            proc.kill()
            proc.wait(timeout=2.0)
        except Exception:
            pass
        tail = " | ".join(last_lines[-3:]) if last_lines else "no output"
        return {"ok": False, "error": f"Tor failed to bootstrap within {int(timeout)}s ({tail})."}


async def ensure_tor_running(
    timeout: float = 90.0,
    socks_port: int = DEFAULT_TOR_SOCKS_PORT,
    control_port: int = DEFAULT_TOR_CONTROL_PORT,
    log_callback: Optional[Callable[[str, str], Any]] = None,
) -> Dict[str, Any]:
    """Ensure Tor binary is installed and managed daemon is bootstrapped at 100% (multi-loop safe)."""
    def log(level: str, msg: str) -> None:
        if log_callback:
            try:
                log_callback(level, msg)
            except Exception:
                pass

    tor_bin = get_tor_bin_path()
    if not tor_bin:
        log("INFO", "[Tor] Tor Expert Bundle not found locally; installing automatically...")
        res = await install_tor()
        if not res.get("success"):
            return {"ok": False, "error": res.get("message", "Tor installation failed.")}
        tor_bin = res["path"]

    return await asyncio.to_thread(_start_and_wait_tor_sync, tor_bin, timeout, socks_port, control_port, log)


async def rotate_tor_circuit(control_port: int = DEFAULT_TOR_CONTROL_PORT) -> Dict[str, Any]:
    """Authenticate against Tor ControlPort and request a clean exit circuit via SIGNAL NEWNYM."""
    cookie_path = TOR_DATA_DIR / "control_auth_cookie"
    auth_cmd = "AUTHENTICATE\r\n"
    if cookie_path.is_file():
        cookie_hex = cookie_path.read_bytes().hex()
        auth_cmd = f"AUTHENTICATE {cookie_hex}\r\n"

    writer: Optional[asyncio.StreamWriter] = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", control_port),
            timeout=5.0,
        )
        writer.write(auth_cmd.encode("ascii"))
        await writer.drain()
        auth_resp = (await asyncio.wait_for(reader.readline(), timeout=5.0)).decode("ascii", errors="replace").strip()
        if not auth_resp.startswith("250"):
            return {"ok": False, "error": f"Tor ControlPort authentication rejected: {auth_resp}"}

        writer.write(b"SIGNAL NEWNYM\r\n")
        await writer.drain()
        nym_resp = (await asyncio.wait_for(reader.readline(), timeout=5.0)).decode("ascii", errors="replace").strip()
        if not nym_resp.startswith("250"):
            return {"ok": False, "error": f"SIGNAL NEWNYM rejected: {nym_resp}"}

        writer.write(b"QUIT\r\n")
        await writer.drain()
    except Exception as exc:
        return {"ok": False, "error": f"Failed to rotate Tor circuit: {exc}"}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    await asyncio.sleep(1.0)
    return {"ok": True, "message": "New Tor circuit activated (SIGNAL NEWNYM)."}


async def get_proxy_exit_ip(proxy_url: str, timeout: float = 15.0) -> Dict[str, Any]:
    """Verify outbound proxy/Tor connectivity and report visible exit IP + Tor exit status."""
    try:
        httpx_proxy = to_httpx_proxy_url(proxy_url)
    except ValueError as exc:
        return {"ok": False, "ip": "", "is_tor": False, "error": str(exc)}

    if not httpx_proxy:
        return {"ok": False, "ip": "", "is_tor": False, "error": "Empty proxy URL."}

    try:
        async with httpx.AsyncClient(
            proxy=httpx_proxy,
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=True,
        ) as client:
            try:
                resp = await client.get("https://check.torproject.org/api/ip")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ok": True,
                        "ip": str(data.get("IP", "")),
                        "is_tor": bool(data.get("IsTor", False)),
                        "proxy_url": httpx_proxy,
                    }
            except Exception:
                pass

            resp2 = await client.get("https://api.ipify.org?format=json")
            if resp2.status_code == 200:
                data2 = resp2.json()
                return {
                    "ok": True,
                    "ip": str(data2.get("ip", "")),
                    "is_tor": False,
                    "proxy_url": httpx_proxy,
                }
            return {
                "ok": False,
                "ip": "",
                "is_tor": False,
                "error": f"Exit IP probe returned HTTP {resp2.status_code}",
            }
    except Exception as exc:
        return {"ok": False, "ip": "", "is_tor": False, "error": f"Proxy connection failed: {exc}"}


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def open_proxied_connection(
    host: str,
    port: int,
    proxy_url: str,
    timeout: float = 10.0,
    use_tls: bool = False,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open an async TCP (and optional TLS) stream tunneled through SOCKS5/SOCKS5h or HTTP CONNECT."""
    validated = validate_proxy_url(proxy_url)
    if not validated:
        raise ValueError("Invalid proxy URL.")

    parsed = urllib.parse.urlparse(validated)
    scheme = parsed.scheme.lower()
    proxy_host = parsed.hostname
    proxy_port = parsed.port
    username = urllib.parse.unquote(parsed.username) if parsed.username is not None else None
    password = urllib.parse.unquote(parsed.password) if parsed.password is not None else None

    if not proxy_host or not proxy_port:
        raise ValueError("Proxy host and port are required.")

    async def _connect_and_handshake() -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
        try:
            if scheme in ("socks5", "socks5h"):
                has_auth = username is not None
                methods = b"\x00\x02" if has_auth else b"\x00"
                writer.write(bytes([0x05, len(methods)]) + methods)
                await writer.drain()

                ver, chosen = await _read_exact(reader, 2)
                if ver != 0x05 or chosen == 0xFF:
                    raise ConnectionError("SOCKS5 proxy rejected authentication methods.")

                if chosen == 0x02:
                    if username is None:
                        raise ConnectionError("SOCKS5 proxy requires username/password authentication.")
                    u_bytes = username.encode("utf-8")
                    p_bytes = (password or "").encode("utf-8")
                    if len(u_bytes) > 255 or len(p_bytes) > 255:
                        raise ValueError("SOCKS5 credentials exceed 255 bytes.")
                    writer.write(bytes([0x01, len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
                    await writer.drain()
                    auth_ver, status = await _read_exact(reader, 2)
                    if auth_ver != 0x01 or status != 0x00:
                        raise ConnectionError("SOCKS5 username/password authentication failed.")
                elif chosen != 0x00:
                    raise ConnectionError(f"Unsupported SOCKS5 auth method selected: {chosen}")

                addr_packet: bytes
                try:
                    ip_obj = ipaddress.ip_address(host)
                    if ip_obj.version == 4:
                        addr_packet = b"\x01" + ip_obj.packed
                    else:
                        addr_packet = b"\x04" + ip_obj.packed
                except ValueError:
                    host_bytes = host.encode("idna")
                    if len(host_bytes) > 255:
                        raise ValueError("Target hostname exceeds SOCKS5 255-byte limit.")
                    addr_packet = bytes([0x03, len(host_bytes)]) + host_bytes

                req = b"\x05\x01\x00" + addr_packet + struct.pack("!H", int(port))
                writer.write(req)
                await writer.drain()

                r_ver, rep, _rsv, atyp = await _read_exact(reader, 4)
                if r_ver != 0x05:
                    raise ConnectionError("Invalid SOCKS5 reply version.")

                if atyp == 0x01:
                    await _read_exact(reader, 4)
                elif atyp == 0x04:
                    await _read_exact(reader, 16)
                elif atyp == 0x03:
                    alen = (await _read_exact(reader, 1))[0]
                    await _read_exact(reader, alen)
                else:
                    raise ConnectionError(f"Invalid SOCKS5 BND.ATYP: {atyp}")
                await _read_exact(reader, 2)

                if rep != 0x00:
                    err_map = {
                        1: "General SOCKS server failure",
                        2: "Connection not allowed by ruleset",
                        3: "Network unreachable",
                        4: "Host unreachable",
                        5: "Connection refused",
                        6: "TTL expired",
                        7: "Command not supported",
                        8: "Address type not supported",
                    }
                    raise ConnectionError(f"SOCKS5 CONNECT {host}:{port} failed: {err_map.get(rep, f'code {rep}')}")

            else:
                if scheme == "https":
                    p_ctx = ssl.create_default_context()
                    await writer.start_tls(p_ctx, server_hostname=proxy_host)

                target_authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
                lines = [f"CONNECT {target_authority} HTTP/1.1", f"Host: {target_authority}"]
                if username is not None:
                    import base64
                    token = base64.b64encode(f"{username}:{password or ''}".encode("utf-8")).decode("ascii")
                    lines.append(f"Proxy-Authorization: Basic {token}")
                req_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
                writer.write(req_bytes)
                await writer.drain()

                status_line = (await reader.readline()).decode("latin-1", errors="replace").strip()
                parts = status_line.split(" ", 2)
                if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) != 200:
                    raise ConnectionError(f"HTTP CONNECT {target_authority} rejected: {status_line or 'empty response'}")
                while True:
                    hdr = await reader.readline()
                    if hdr in (b"\r\n", b"\n", b""):
                        break

            if use_tls:
                ctx = ssl_context or ssl.create_default_context()
                await writer.start_tls(ctx, server_hostname=host)

            return reader, writer
        except Exception:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    return await asyncio.wait_for(_connect_and_handshake(), timeout=timeout)
