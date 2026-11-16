#!/usr/bin/env python3
"""compliance-guardian entry point. Usage: python3 cg.py --help"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cg.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
