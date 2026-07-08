#!/usr/bin/env python3
"""
inject_invalid_link.py  -- inject an invalid link into an early_hints persist file.

Usage: inject_invalid_link.py <persist_file>

Reads the binary persist file, finds the first entry, appends an invalid
rel=prefetch link to its link list, and re-serializes the file.
Used by the early_hints_persist_load_validation gold test to create a
"tampered persist file" scenario that triggers the load validation code path.
"""
import struct
import sys
import os

HINTS_CACHE_MAGIC = 0x45480003  # v3: no learn_count; key + last_updated + links
INVALID_LINK      = b"</injected-bad.js>; rel=prefetch"


def inject(path):
    with open(path, "rb") as f:
        data = f.read()

    offset = 0
    magic, entry_count = struct.unpack_from("<II", data, offset)
    offset += 8

    if magic != HINTS_CACHE_MAGIC:
        print(f"ERROR: bad magic 0x{magic:08x}", file=sys.stderr)
        sys.exit(1)

    if entry_count == 0:
        print("ERROR: no entries in file", file=sys.stderr)
        sys.exit(1)

    # Parse first entry header
    key_len, = struct.unpack_from("<H", data, offset)
    offset += 2
    key = data[offset:offset + key_len]
    offset += key_len

    # v3 format: last_updated (uint64) follows key directly (no learn_count)
    last_updated, = struct.unpack_from("<Q", data, offset)
    offset += 8

    link_count, = struct.unpack_from("<H", data, offset)
    offset += 2

    # Read existing links
    links = []
    for _ in range(link_count):
        ll, = struct.unpack_from("<H", data, offset)
        offset += 2
        links.append(data[offset:offset + ll])
        offset += ll

    # Inject the invalid link
    links.append(INVALID_LINK)
    new_link_count = len(links)

    # Re-serialize everything (v3 format: no learn_count)
    out = struct.pack("<II", HINTS_CACHE_MAGIC, entry_count)
    out += struct.pack("<H", key_len) + key
    out += struct.pack("<Q", last_updated)
    out += struct.pack("<H", new_link_count)
    for lnk in links:
        out += struct.pack("<H", len(lnk)) + lnk

    # Append remaining entries unchanged (if any)
    out += data[offset:]

    # Atomic write
    tmp = path + ".inject.tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.rename(tmp, path)
    print(f"INJECTED: {len(links)} links ({new_link_count - link_count} added) in {path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <persist_file>", file=sys.stderr)
        sys.exit(1)
    inject(sys.argv[1])
