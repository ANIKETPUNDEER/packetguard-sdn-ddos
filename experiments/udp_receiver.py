"""Receive bounded UDP lab traffic and write per-source delivery counters."""
from __future__ import annotations

import argparse
import json
import socket
import time
from collections import defaultdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration <= 0:
        parser.error("duration must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.port))
    sock.settimeout(0.2)
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    started = time.monotonic()
    while time.monotonic() - started < args.duration:
        try:
            payload, address = sock.recvfrom(65535)
        except socket.timeout:
            continue
        source = counts[address[0]]
        source["packets"] += 1
        source["bytes"] += len(payload)
    elapsed = time.monotonic() - started
    sock.close()
    sources = {
        address: {**counter, "receiver_mbps": counter["bytes"] * 8 / elapsed / 1_000_000}
        for address, counter in counts.items()
    }
    args.output.write_text(json.dumps({
        "scope": "server-observed bounded lab UDP traffic", "duration_s": elapsed,
        "sources": sources}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
