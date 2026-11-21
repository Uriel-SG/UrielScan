import argparse
import atexit
import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "urielscan.log"
PID_FILE = DATA_DIR / "urielscan.pid"


def _configure_windowless_streams() -> None:
    """Redirect None stdout/stderr (when launched via pythonw.exe) to data/urielscan.log."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
    if sys.stdout is None:
        sys.stdout = log_fh
    if sys.stderr is None:
        sys.stderr = log_fh


def _is_port_listening(host: str, port: int, timeout: float = 0.35) -> bool:
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    try:
        with socket.create_connection((probe_host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _remove_pid_file() -> None:
    try:
        if PID_FILE.is_file() and PID_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()):
            PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass


def print_banner(host: str, port: int):
    banner = rf"""
========================================================================
   _   _      _      _  ____                   
  | | | |_ __(_) ___| |/ ___|  ___ __ _ _ __   
  | | | | '__| |/ _ \ | \___ \ / __/ _` | '_ \  
  | |_| | |  | |  __/ |  ___) | (_| (_| | | | | 
   \___/|_|  |_|\___|_| |____/ \___\__,_|_| |_| 
                                                
  URIELSCAN - Next-Generation Purple Team Vulnerability Platform
========================================================================
  [+] Server avviato su : http://{host}:{port}
  [+] Documentazione API: http://{host}:{port}/docs
  [+] Premere CTRL+C o eseguire stop.bat per arrestare il servizio.
========================================================================
"""
    print(banner)


def main():
    _configure_windowless_streams()

    parser = argparse.ArgumentParser(description="UrielScan Application Runner")
    parser.add_argument("--host", default="127.0.0.1", help="Indirizzo IP di ascolto (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Porta di ascolto (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Abilita il live reload per lo sviluppo")
    parser.add_argument("--no-browser", action="store_true", help="Non aprire automaticamente il browser all'avvio")

    args = parser.parse_args()

    # Ensure current directory is in sys.path
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    browse_host = "127.0.0.1" if args.host in ("0.0.0.0", "::", "") else args.host
    url = f"http://{browse_host}:{args.port}"

    # If UrielScan is already listening on this port, open the dashboard cleanly and exit
    if _is_port_listening(browse_host, args.port):
        print(f"[+] UrielScan e gia in esecuzione su {url}.")
        if not args.no_browser:
            webbrowser.open(url)
        return

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    atexit.register(_remove_pid_file)

    # Auto-open browser as soon as the HTTP port starts accepting connections
    if not args.no_browser:
        def open_browser():
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                if _is_port_listening(browse_host, args.port):
                    webbrowser.open(url)
                    return
                time.sleep(0.25)
            webbrowser.open(url)

        threading.Thread(target=open_browser, daemon=True).start()

    print_banner(args.host, args.port)

    is_tty = bool(sys.stdout and hasattr(sys.stdout, "isatty") and sys.stdout.isatty())
    try:
        import uvicorn
        uvicorn.run(
            "backend.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            use_colors=is_tty,
        )
    finally:
        _remove_pid_file()


if __name__ == "__main__":
    main()
