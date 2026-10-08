"""
Executable module entry point for AegisExec.
Allows running with `python3 -m aegisexec`.
"""

import sys
from aegisexec.cli import main

if __name__ == "__main__":
    sys.exit(main())
