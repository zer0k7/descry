from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional


class InputError(Exception):
    pass


def read_input(value: Optional[str] = None, file: Optional[str] = None) -> str:
    if value is not None and file is not None:
        raise InputError("provide either TEXT or --file, not both")
    if file is not None:
        try:
            text = Path(file).read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            raise InputError(f"cannot read {file}: file is not UTF-8 text") from error
        except OSError as error:
            reason = error.strerror or str(error)
            raise InputError(f"cannot read {file}: {reason}") from error
        return text.rstrip("\r\n")
    if value is not None and value != "-":
        return value
    if sys.stdin.isatty():
        raise InputError(
            "no input given; pass TEXT, use --file FILE, or pipe data into stdin"
        )
    text = sys.stdin.read().rstrip("\r\n")
    if not text:
        raise InputError("stdin was empty; pass TEXT, use --file FILE, or pipe data")
    return text
