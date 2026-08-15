#!/usr/bin/env python3
"""Backward-compatible entry point for tools/sender/udp_sender.py."""

from pathlib import Path
import runpy


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "sender" / "udp_sender.py"
    runpy.run_path(str(target), run_name="__main__")
