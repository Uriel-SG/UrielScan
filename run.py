import sys
import os
import argparse
import webbrowser
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


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
  [+] Premere CTRL+C per arrestare il servizio.
========================================================================
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(description="UrielScan Application Runner")
    parser.add_argument("--host", default="127.0.0.1", help="Indirizzo IP di ascolto (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Porta di ascolto (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Abilita il live reload per lo sviluppo")
    parser.add_argument("--no-browser", action="store_true", help="Non aprire automaticamente il browser all'avvio")

    args = parser.parse_args()

    # Ensure current directory is in sys.path
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    # Auto-open browser in a separate thread if requested
    if not args.no_browser:
        def open_browser():
            time.sleep(1.5)
            webbrowser.open(f"http://{args.host}:{args.port}")
        threading.Thread(target=open_browser, daemon=True).start()

    print_banner(args.host, args.port)

    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )


if __name__ == "__main__":
    main()
