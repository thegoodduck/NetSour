#!/usr/bin/env python3
"""Legacy entry point.

The application now lives in the `netsour` package. This shim keeps
`sudo python main.py` working; `python -m netsour` and the `netsour` console
script are the preferred invocations.
"""

import sys

from netsour.cli import main

if __name__ == "__main__":
    sys.exit(main())
