#!/usr/bin/env python3
"""Thin launcher - users still run: python chumbucket.py [args]."""
import sys
from chumbucket.cli import main
from chumbucket.ui import say

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("\nInterrupted - no challenge written. See you next tide. \U0001F41F",
            "warning")
        sys.exit(130)
