#!/usr/bin/env python
"""
Standard Launcher for the SKIDY Framework
"""

import sys
import traceback

from core.framework import Framework


def main():
    framework = Framework()
    try:
        framework.run(sys.argv[1:])
    except KeyboardInterrupt:
        framework.ctrlc()
    except Exception:
        print("*** print_exc:")
        traceback.print_exc()
        


if __name__ == "__main__":
    main()
