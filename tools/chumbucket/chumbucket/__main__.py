"""Entry point: python -m chumbucket."""
import sys
from .cli import main
from .ui import say

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        say("\nInterrupted - no challenge written. See you next tide. \U0001F41F",
            "warning")
        sys.exit(130)
