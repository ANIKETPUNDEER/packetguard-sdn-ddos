"""Send bounded UDP traffic and record what this client offered to the lab."""
from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--rate-bps", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration <= 0 or args.rate_bps <= 0:
        parser.error("duration and rate-bps must be positive")

    payload = b"P" * 1400
    interval = len(payload) * 8 / args.rate_bps
    sent_packets = sent_bytes = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    started = time.monotonic()
    next_send = started
    while time.monotonic() - started < args.duration:
        sock.sendto(payload, (args.target, args.port))
        sent_packets += 1
        sent_bytes += len(payload)
        next_send += interval
        time.sleep(max(0.0, next_send - time.monotonic()))
    elapsed = time.monotonic() - started
    sock.close()
    args.output.write_text(json.dumps({
        "scope": "bounded lab UDP sender", "target": args.target,
        "port": args.port, "duration_s": elapsed, "sent_packets": sent_packets,
        "sent_bytes": sent_bytes, "offered_mbps": sent_bytes * 8 / elapsed / 1_000_000,
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
