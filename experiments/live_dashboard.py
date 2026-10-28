"""Live four-panel Matplotlib dashboard for the Ryu PacketGuard REST metrics."""
import argparse
import time
from collections import deque
from urllib.request import urlopen
import json

import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080/stats/packetguard")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--points", type=int, default=120)
    args = parser.parse_args()
    if args.interval < 0.5 or args.points < 10:
        parser.error("interval must be >= 0.5 seconds and points >= 10")

    times = deque(maxlen=args.points)
    values = {key: deque(maxlen=args.points) for key in
              ("packet_in", "switch_flow_entries", "allow", "throttle", "block",
               "switch_packet_count", "switch_byte_count")}
    started = time.monotonic()
    fig, axes = plt.subplots(2, 2, figsize=(11, 7))
    ax_packet, ax_flows, ax_actions, ax_rates = axes.flat
    fig.suptitle("PacketGuard live SDN dashboard")

    def update(_frame):
        try:
            with urlopen(args.url, timeout=1.5) as response:
                metrics = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            fig.suptitle(f"PacketGuard live SDN dashboard — controller unavailable ({exc})")
            return
        t = time.monotonic() - started
        times.append(t)
        for key in values:
            values[key].append(float(metrics.get(key, 0) or 0))
        x = list(times)

        ax_packet.clear(); ax_packet.plot(x, values["packet_in"], color="#2563eb")
        ax_packet.set(title="Cumulative Packet-In messages", xlabel="Seconds", ylabel="Messages")
        ax_flows.clear(); ax_flows.plot(x, values["switch_flow_entries"], color="#7c3aed")
        ax_flows.set(title="Active OpenFlow entries", xlabel="Seconds", ylabel="Entries")
        ax_actions.clear()
        for name, color in (("allow", "#16a34a"), ("throttle", "#d97706"), ("block", "#dc2626")):
            ax_actions.plot(x, values[name], label=name, color=color)
        ax_actions.set(title="Cumulative policy decisions", xlabel="Seconds", ylabel="Decisions")
        ax_actions.legend(loc="upper left")
        ax_rates.clear()
        series = list(values["switch_byte_count"])
        rates = [0.0]
        for i in range(1, len(series)):
            dt = max(0.001, x[i] - x[i-1])
            rates.append(max(0.0, series[i] - series[i-1]) / dt)
        ax_rates.plot(x, rates, color="#be123c")
        ax_rates.set(title="Observed switch byte rate", xlabel="Seconds", ylabel="Bytes/s")
        for ax in axes.flat:
            ax.grid(True, alpha=.25)
        fig.suptitle(f"PacketGuard live SDN dashboard — {metrics.get('datapath_count', 0)} switches; "
                     f"model loaded: {metrics.get('model_loaded', False)}")
        fig.tight_layout(rect=(0, 0, 1, .95))

    animation = FuncAnimation(fig, update, interval=int(args.interval * 1000),
                              cache_frame_data=False)
    # Keep the animation referenced for the lifetime of the interactive window.
    fig._packetguard_animation = animation
    plt.show()


if __name__ == "__main__":
    main()
