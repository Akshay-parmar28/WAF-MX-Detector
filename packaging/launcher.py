"""PyInstaller entry point (absolute imports so the frozen app starts cleanly)."""
import sys

from wafmx.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
