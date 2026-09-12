"""Pytest path setup: make the `core/` modules importable in tests."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_DIR = os.path.join(REPO_ROOT, "core")

for path in (REPO_ROOT, CORE_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)
