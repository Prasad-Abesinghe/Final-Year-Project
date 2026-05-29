#!/usr/bin/env python3
"""
SHIELD-GH Dashboard launcher.
Starts the FastAPI backend and prints the URLs.
Run the frontend separately: cd frontend && npm run dev
"""
import subprocess, sys, os, webbrowser, time
from pathlib import Path

BACKEND_DIR = Path(__file__).parent / "backend"

def main():
    print("=" * 50)
    print("  SHIELD-GH Dashboard")
    print("=" * 50)
    print(f"\n[1] Starting FastAPI backend on http://localhost:8000")
    print(f"[2] Open frontend:  cd shield_gh_dashboard/frontend && npm run dev")
    print(f"    Then open:      http://localhost:5173\n")

    os.chdir(BACKEND_DIR)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--port", "8000"],
        cwd=str(BACKEND_DIR)
    )
    time.sleep(2)
    print("\n[BACKEND] Running. Press Ctrl+C to stop.")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\n[STOPPED]")

if __name__ == "__main__":
    main()
