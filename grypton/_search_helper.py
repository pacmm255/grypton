"""Time-isolated byte-regex matching for :func:`grypton.tools.local_analyze`.

This module is an implementation detail.  The parent process owns path
validation and opens the file without following symlinks; this child receives
only that already-open descriptor and emits bounded match offsets.
"""
from __future__ import annotations

import json
import os
import re
import sys


_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_PATTERN_BYTES = 4096
_MAX_MATCHES = 51


def _read_file(fd: int) -> bytes:
    size = os.fstat(fd).st_size
    if size > _MAX_FILE_BYTES:
        raise ValueError("analysis input exceeds the 64 MB limit")
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main() -> int:
    try:
        fd = int(sys.argv[1])
        request = json.loads(sys.stdin.read())
        pattern = str(request.get("pattern") or "").encode("utf-8")
        if not pattern:
            raise ValueError("search pattern must not be empty")
        if len(pattern) > _MAX_PATTERN_BYTES:
            raise ValueError("search pattern exceeds the 4096-byte limit")
        limit = max(1, min(int(request.get("limit", _MAX_MATCHES)), _MAX_MATCHES))
        flags = re.IGNORECASE if request.get("ignore_case") else 0
        try:
            expression = re.compile(pattern, flags)
        except re.error as exc:
            raise ValueError(f"invalid regular expression: {exc}") from exc

        data = _read_file(fd)
        positions: list[list[int]] = []
        for match in expression.finditer(data):
            positions.append([match.start(), match.end()])
            if len(positions) >= limit:
                break
        print(json.dumps({"ok": True, "positions": positions}, separators=(",", ":")))
        return 0
    except (IndexError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
