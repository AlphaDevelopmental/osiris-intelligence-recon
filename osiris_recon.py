#!/usr/bin/env python3
"""OSIRIS Intelligence Recon — entry point.

Independent community project using the OSIRIS API (https://osirisai.live);
not an official OSIRIS product. See README.md.
"""

import sys

from osiris.cli import main

if __name__ == "__main__":
    sys.exit(main())
