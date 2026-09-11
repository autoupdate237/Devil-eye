"""PyInstaller entry point for DevilsEye.exe.

The real CLI lives in ``devils_eye.__main__`` and uses package-relative
imports, so it must be imported *as part of the package* — never passed to
PyInstaller directly as the launch script. This thin wrapper keeps the
package context intact.
"""

import sys

from devils_eye.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
