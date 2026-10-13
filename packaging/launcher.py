"""PyInstaller entrypoint. Installed ddt package remains the only implementation."""
from ddt.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
