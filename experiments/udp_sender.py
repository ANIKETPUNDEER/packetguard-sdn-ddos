"""Send bounded UDP traffic from one or more real Mininet interface addresses."""
from __future__ import annotations

import argparse
import json
import socket
import time
from collections import Counter
from pathlib import Path


def sources_from_file(path: Path) -> list[str]:
    try:
        values = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    except OSError as exc:
        raise argparse.ArgumentTypeError(f"could not read source file: {exc}") from exc
    return [value for value in values if value and not value.startswith("#")]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=5201)
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--rate-bps", type=int, required=True,
                        help="aggregate offered rate across every selected source")
    parser.add_argument("--source", action="append", default=[],
                        help="real address configured on this Mininet host; may repeat")
    parser.add_argument("--source-file", type=Path,
                        help="one real configured source address per line")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration <= 0 or args.rate_bps <= 0:
        parser.error("duration and rate-bps must be positive")
    sources = list(args.source)
    if args.source_file:
        sources.extend(sources_from_file(args.source_file))
    if len(sources) != len(set(sources)):
        parser.error("source addresses must be unique")

    payload = b"P" * 1400
    interval = len(payload) * 8 / args.rate_bps
    sockets: list[tuple[str | None, socket.socket]] = []
    try:
        if sources:
            for source in sources:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.bind((source, 0))
                sockets.append((source, sock))
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sockets.append((None, sock))
        sent_packets = sent_bytes = local_drop_packets = 0
        per_source_packets: Counter[str] = Counter()
        started = time.monotonic()
        next_send = started
        index = 0
        while time.monotonic() - started < args.duration:
            source, sock = sockets[index]
            try:
                sock.sendto(payload, (args.target, args.port))
            except (BlockingIOError, InterruptedError):
                # A full local queue is recorded as a local drop. The bounded
                # sender never waits beyond its configured duration.
                local_drop_packets += 1
            else:
                sent_packets += 1
                sent_bytes += len(payload)
                if source is not None:
                    per_source_packets[source] += 1
            index = (index + 1) % len(sockets)
            next_send += interval
            time.sleep(max(0.0, next_send - time.monotonic()))
        elapsed = time.monotonic() - started
    finally:
        for _, sock in sockets:
            sock.close()
    args.output.write_text(json.dumps({
        "scope": "bounded lab UDP sender", "target": args.target,
        "port": args.port, "duration_s": elapsed, "sent_packets": sent_packets,
        "sent_bytes": sent_bytes, "offered_mbps": sent_bytes * 8 / elapsed / 1_000_000,
        "configured_source_count": len(sources),
        "local_drop_packets": local_drop_packets,
        "per_source_packets": dict(per_source_packets),
    }, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()

