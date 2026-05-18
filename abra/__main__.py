"""Module entrypoint for ``python3 -m abra``."""

from __future__ import annotations

from abra.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
