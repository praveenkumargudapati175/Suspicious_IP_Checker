from __future__ import annotations

import ipaddress
import re
from pathlib import Path


IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def log_file_identity(log_path: Path) -> tuple[int, int]:
    """Return a stable per-file identity so callers can detect log rotation."""
    stat = log_path.stat()
    return stat.st_dev, stat.st_ino


def read_new_lines(log_path: Path, offset: int) -> tuple[list[str], int]:
    """Read appended UTF-8 text from a byte offset, handling truncation/rotation."""
    with log_path.open("rb") as file:
        file.seek(0, 2)
        end = file.tell()
        if offset < 0 or offset > end:
            offset = 0
        file.seek(offset)
        content = file.read()
    return content.decode("utf-8", errors="replace").splitlines(), end


def extract_ipv4_addresses(lines: list[str]) -> list[str]:
    addresses: list[str] = []
    seen: set[str] = set()
    for line in lines:
        for candidate in IPV4_PATTERN.findall(line):
            try:
                address = ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            normalized = str(address)
            if normalized not in seen:
                seen.add(normalized)
                addresses.append(normalized)
    return addresses
