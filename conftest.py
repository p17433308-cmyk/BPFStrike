"""Make `pytest tests/` work from a fresh clone without `pip install -e .`
by putting the repo root (which contains the `bpfstrike` package) on sys.path.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
