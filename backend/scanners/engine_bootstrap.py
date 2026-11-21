"""Automatic startup provisioning and live state tracker for UrielScan scanning engines."""

import asyncio
import copy
import os
import sys
import threading
from typing import Any, Dict

from backend.scanners.nmap_engine import detect_nmap, install_nmap
from backend.scanners.nuclei_engine import detect_nuclei, install_nuclei
from backend.scanners.zap_engine import detect_zap, install_zap
from backend.scanners.tor_engine import detect_tor, install_tor

_STATE_LOCK = threading.Lock()
_RUN_LOCK = threading.Lock()

BOOTSTRAP_STATE: Dict[str, Any] = {
    "running": False,
    "completed": False,
    "engines": {
        "nmap": {"status": "idle", "message": ""},
        "nuclei": {"status": "idle", "message": ""},
        "zap": {"status": "idle", "message": ""},
        "tor": {"status": "idle", "message": ""},
    },
}


def get_bootstrap_state() -> Dict[str, Any]:
    with _STATE_LOCK:
        return copy.deepcopy(BOOTSTRAP_STATE)


def _set_engine_state(engine: str, status: str, message: str = "") -> None:
    with _STATE_LOCK:
        BOOTSTRAP_STATE["engines"][engine] = {"status": status, "message": message}


async def ensure_all_engines(force: bool = False) -> Dict[str, Any]:
    """Check Nmap, Nuclei, OWASP ZAP, and Tor and install any missing engines sequentially."""
    if not _RUN_LOCK.acquire(blocking=False):
        return get_bootstrap_state()

    try:
        with _STATE_LOCK:
            BOOTSTRAP_STATE["running"] = True
            BOOTSTRAP_STATE["completed"] = False

        checks = [
            ("nmap", detect_nmap, install_nmap),
            ("nuclei", detect_nuclei, install_nuclei),
            ("zap", detect_zap, install_zap),
            ("tor", detect_tor, install_tor),
        ]

        for name, detect_fn, install_fn in checks:
            det = detect_fn()
            if det.get("installed") and not force:
                _set_engine_state(name, "installed", det.get("version") or "ready")
                continue

            _set_engine_state(name, "installing", f"Installing {name}...")
            print(f"[UrielScan Bootstrap] Installing missing engine: {name}...")
            try:
                res = await install_fn()
                if res.get("success"):
                    _set_engine_state(name, "installed", res.get("message", "installed"))
                    print(f"[UrielScan Bootstrap] {name}: OK - {res.get('message', '')}")
                else:
                    _set_engine_state(name, "failed", res.get("message", "install failed"))
                    print(f"[UrielScan Bootstrap] {name}: WARN - {res.get('message', '')}")
            except Exception as exc:
                _set_engine_state(name, "failed", str(exc))
                print(f"[UrielScan Bootstrap] {name}: ERROR - {exc}")

        with _STATE_LOCK:
            BOOTSTRAP_STATE["running"] = False
            BOOTSTRAP_STATE["completed"] = True
        return get_bootstrap_state()
    finally:
        with _STATE_LOCK:
            BOOTSTRAP_STATE["running"] = False
        _RUN_LOCK.release()


def start_engine_bootstrap_background(force: bool = False, allow_in_test: bool = False) -> bool:
    """Launch missing-engine auto-installer in a background daemon thread at startup."""
    if not allow_in_test:
        if os.getenv("URIELSCAN_SKIP_AUTO_INSTALL") == "1" or "pytest" in sys.modules or os.getenv("PYTEST_CURRENT_TEST"):
            return False

    missing = []
    for name, detect_fn in (
        ("nmap", detect_nmap),
        ("nuclei", detect_nuclei),
        ("zap", detect_zap),
        ("tor", detect_tor),
    ):
        det = detect_fn()
        if det.get("installed"):
            _set_engine_state(name, "installed", det.get("version") or "ready")
        else:
            missing.append(name)
            _set_engine_state(name, "pending", f"Queued for auto-install ({name})")

    if not missing and not force:
        with _STATE_LOCK:
            BOOTSTRAP_STATE["running"] = False
            BOOTSTRAP_STATE["completed"] = True
        return False

    if _RUN_LOCK.locked():
        return False

    def _worker() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(ensure_all_engines(force=force))
        finally:
            try:
                loop.close()
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True, name="urielscan-engine-bootstrap").start()
    return True


def main() -> int:
    """CLI entrypoint used by first-time installers to provision all engines synchronously."""
    state = asyncio.run(ensure_all_engines(force=False))
    engines = state.get("engines", {})
    all_ok = True
    print("\n=== UrielScan Engines Provisioning Summary ===")
    for name in ("nmap", "nuclei", "zap", "tor"):
        info = engines.get(name, {})
        st = info.get("status", "unknown")
        msg = info.get("message", "")
        print(f"  - {name:<7}: {st.upper():<9} {msg}")
        if st != "installed":
            all_ok = False
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
