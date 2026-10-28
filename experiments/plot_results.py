"""Plot the live Mininet time series from results/live/timeline.csv."""
import argparse
import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("results/live"))
    parser.add_argument("--output", type=Path, default=Path("results/live/plots"))
    args = parser.parse_args()
    with (args.input / "timeline.csv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit("No timeline samples found. Run experiments/run_lab.py first.")
    args.output.mkdir(parents=True, exist_ok=True)
    x = [float(r["elapsed_s"]) for r in rows]
    for field, title, ylabel, filename in [
        ("ovs_flow_entries", "OpenFlow entries over time", "Flow entries", "flow_entries.png"),
        ("packet_in", "Controller Packet-In events", "Cumulative Packet-In events", "packet_in.png"),
        ("ovs_byte_count", "OVS bytes observed", "Cumulative bytes", "ovs_bytes.png")]:
        y = [float(r.get(field) or 0) for r in rows]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.plot(x, y, marker="o", linewidth=1.8)
        ax.set(title=title, xlabel="Elapsed time (s)", ylabel=ylabel)
        ax.grid(True, alpha=.25); fig.tight_layout()
        fig.savefig(args.output / filename, dpi=150); plt.close(fig)
    # Action counters are cumulative in the Ryu REST payload; plot their
    # successive differences as per-sample decisions.
    if all(name in rows[0] for name in ("allow", "throttle", "block")):
        fig, ax = plt.subplots(figsize=(8, 4.5))
        for name in ("allow", "throttle", "block"):
            values = [int(float(r.get(name) or 0)) for r in rows]
            deltas = [values[0]] + [max(0, b-a) for a, b in zip(values, values[1:])]
            ax.plot(x, deltas, marker="o", label=name)
        ax.set(title="Per-sample graduated mitigation decisions", xlabel="Elapsed time (s)",
               ylabel="Decisions per sample")
        ax.legend(); ax.grid(True, alpha=.25); fig.tight_layout()
        fig.savefig(args.output / "mitigation_actions.png", dpi=150); plt.close(fig)
    # iperf3 JSON contains one-second intervals; plot the measured benign TCP
    # receiver goodput when that client completed successfully.
    iperf_path = args.input / "iperf-benign.json"
    if iperf_path.exists():
        try:
            iperf = json.loads(iperf_path.read_text(encoding="utf-8"))
            intervals = iperf.get("intervals", [])
            t = [float(i["sum"]["end"]) for i in intervals]
            mbps = [float(i["sum"]["bits_per_second"])/1_000_000 for i in intervals]
            if t:
                fig, ax = plt.subplots(figsize=(8, 4.5))
                ax.plot(t, mbps, marker="o", linewidth=1.8)
                ax.set(title="Measured benign TCP goodput (iperf3)",
                       xlabel="Elapsed time (s)", ylabel="Receiver goodput (Mbps)")
                ax.grid(True, alpha=.25); fig.tight_layout()
                fig.savefig(args.output / "benign_goodput.png", dpi=150); plt.close(fig)
        except (ValueError, KeyError, TypeError):
            print("Could not parse benign iperf JSON; skipped goodput plot.")
    print(f"Plots saved in {args.output}")


if __name__ == "__main__":
    main()
