"""Run a bounded, isolated Mininet experiment against a running Ryu app.

Only Mininet hosts created by this script originate traffic. Source addresses
are not forged. The total UDP test rate is capped at 10 Mbps.
"""
from __future__ import annotations

import argparse
import csv
import json
import ipaddress
import re
import sys
import time
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, RemoteController

from topology.packetguard_topo import PacketGuardTopo


def controller_metrics(url: str) -> tuple[dict, float | None]:
    started = time.perf_counter()
    try:
        with urlopen(url, timeout=1) as response:
            metrics = json.loads(response.read().decode("utf-8"))
        return metrics, (time.perf_counter() - started) * 1000
    except Exception:
        return {}, None


def iperf_summary(path: Path, measured_from_s: float = 0.0,
                  measured_duration_s: float | None = None) -> dict:
    if not path.exists():
        return {"available": False}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        receiver_report = payload
        server_json = payload.get("server_output_json")
        if isinstance(server_json, str):
            server_json = json.loads(server_json)
        if isinstance(server_json, dict):
            receiver_report = server_json
        elif measured_from_s > 0:
            return {"available": False,
                    "error": "iperf JSON lacks server-side receiver intervals"}
        end = receiver_report.get("end", {})
        result = end.get("sum_received") or end.get("sum") or {}
        if measured_from_s > 0:
            intervals = []
            for interval in receiver_report.get("intervals", []):
                sample = interval.get("sum_received") or interval.get("sum") or {}
                streams = interval.get("streams") or [{}]
                start = float(sample.get("start", streams[0].get("start", 0)))
                finish = float(sample.get("end", streams[0].get("end", 0)))
                measured_to_s = (measured_from_s + measured_duration_s
                                 if measured_duration_s is not None else float("inf"))
                if (sample.get("sender") is not True
                        and start >= measured_from_s and finish > start
                        and finish <= measured_to_s + 0.05):
                    intervals.append((start, finish, float(sample.get("bits_per_second", 0))))
            if intervals:
                measured_seconds = sum(finish - start for start, finish, _ in intervals)
                if (measured_duration_s is not None
                        and measured_seconds < measured_duration_s * 0.99):
                    return {"available": False,
                            "error": "iperf JSON does not cover the full measured interval",
                            "measured_seconds": measured_seconds}
                measured_bits = sum(rate * (finish - start)
                                    for start, finish, rate in intervals)
                receiver_mbps = measured_bits / measured_seconds / 1_000_000
            else:
                return {"available": False,
                        "error": "iperf JSON has no post-warmup receiver intervals"}
        else:
            receiver_mbps = float(result.get("bits_per_second", 0)) / 1_000_000
        summary = {"available": True, "receiver_mbps": receiver_mbps,
                   "measured_from_s": measured_from_s}
        if "lost_packets" in result:
            sent = int(result.get("packets", 0))
            lost = int(result.get("lost_packets", 0))
            summary.update({"lost_packets": lost, "packets": sent,
                            "loss_fraction": lost / sent if sent else None,
                            "jitter_ms": result.get("jitter_ms")})
        return summary
    except (OSError, ValueError, TypeError):
        return {"available": False, "error": "iperf JSON could not be parsed"}


def udp_sender_summary(path: Path) -> dict:
    if not path.exists():
        return {"available": False, "error": "sender output missing"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return {"available": True, **payload}
    except (OSError, ValueError, TypeError):
        return {"available": False, "error": "sender output could not be parsed"}

def udp_receiver_summary(path: Path, hosts: dict[str, str]) -> dict:
    if not path.exists():
        return {name: {"available": False, "error": "receiver output missing"}
                for name in hosts}
    try:
        received = json.loads(path.read_text(encoding="utf-8")).get("sources", {})
        return {
            name: {"available": True, **received.get(address, {
                "packets": 0, "bytes": 0, "receiver_mbps": 0.0})}
            for name, address in hosts.items()
        }
    except (OSError, ValueError, TypeError):
        return {name: {"available": False, "error": "receiver output could not be parsed"}
                for name in hosts}


def parse_rate(value: str) -> int:
    match = re.fullmatch(r"(\d+)([kKmM])", value)
    if not match:
        raise argparse.ArgumentTypeError("rate must look like 250K, 1M, or 10M")
    number, unit = int(match.group(1)), match.group(2).lower()
    return number * (1000 if unit == "k" else 1_000_000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--udp-rate", type=parse_rate, default=1_000_000,
                        help="aggregate test rate, maximum 10M (default 1M)")
    parser.add_argument("--multi-vector", action="store_true",
                        help="also send bounded SYN and ICMP probes from lab-only hosts")
    parser.add_argument("--capture-pcap", action="store_true",
                        help="capture traffic at the destination host for later CICFlowMeter conversion")
    parser.add_argument("--output", type=Path, default=Path("results/live"))
    parser.add_argument("--controller-url", default="http://127.0.0.1:8080/stats/packetguard")
    parser.add_argument("--setup", choices=("none", "per-flow", "intent"),
                        help="comparison setup label; verified against the controller REST mode")
    parser.add_argument("--no-attack", action="store_true",
                        help="run only the benign TCP baseline; do not start UDP senders")
    parser.add_argument("--source-count", type=int, default=0,
                        help="number of real attack-source aliases; 0 uses the four primary attacker addresses")
    parser.add_argument("--attack-prefix",
                        help="reserved IPv4 prefix used only when --source-count is nonzero")
    args = parser.parse_args()
    if not 5 <= args.duration <= 120:
        parser.error("duration must be between 5 and 120 seconds")
    if not 1 <= args.udp_rate <= 10_000_000:
        parser.error("aggregate UDP rate must be between 1 bit/s and 10 Mbps")

    if args.source_count < 0:
        parser.error("source-count must be non-negative")
    if args.source_count and args.no_attack:
        parser.error("source-count cannot be used with --no-attack")
    alias_network = None
    if args.source_count:
        if not args.attack_prefix:
            parser.error("--attack-prefix is required when --source-count is used")
        try:
            alias_network = ipaddress.ip_network(args.attack_prefix, strict=False)
        except ValueError as exc:
            parser.error(f"invalid attack-prefix: {exc}")
        if alias_network.version != 4 or args.source_count > alias_network.num_addresses - 2:
            parser.error("attack-prefix must contain enough usable IPv4 addresses")
        topology_network = ipaddress.ip_network("10.0.0.0/24")
        if alias_network.overlaps(topology_network):
            parser.error("attack-prefix must not overlap the Mininet host subnet 10.0.0.0/24")
    setLogLevel("warning")
    net = Mininet(topo=PacketGuardTopo(), controller=None, link=TCLink,
                  switch=OVSKernelSwitch, autoSetMacs=True, autoStaticArp=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    args.output.mkdir(parents=True, exist_ok=True)
    clients = []
    servers = []
    captures = []
    timeline = []
    try:
        net.start()
        time.sleep(2)
        print(f"PacketGuard: traffic run started; collecting for {args.duration} seconds.",
              flush=True)
        h1, h2 = net.get("h1"), net.get("h2")
        alias_assignments: dict[str, list[str]] = {name: [] for name in ("a1", "a2", "a3", "a4")}
        if alias_network is not None:
            usable = iter(alias_network.hosts())
            for index in range(args.source_count):
                name = ("a1", "a2", "a3", "a4")[index % 4]
                address = str(next(usable))
                host = net.get(name)
                # Bind each source as a host route. Applying the large pool's
                # subnet mask to every alias creates overlapping connected
                # routes and can make Linux claim that unrelated hosts share
                # the alias pool's L2 subnet.
                result = host.cmd(f"ip addr add {address}/32 dev {host.defaultIntf()}")
                if result.strip():
                    raise RuntimeError(f"could not configure {address} on {name}: {result.strip()}")
                alias_assignments[name].append(address)
            for name, addresses in alias_assignments.items():
                (args.output / f"sources-{name}.txt").write_text("\n".join(addresses) + "\n",
                                                                     encoding="utf-8")
        project_root = Path(__file__).resolve().parents[1]
        receiver_output = args.output / "udp_receiver.json"
        pcap_path = (args.output / "mininet_h1.pcap").resolve()
        if args.capture_pcap:
            capture = h1.popen(["tcpdump", "-U", "-n", "-i", "h1-eth0",
                                "-w", str(pcap_path)],
                               stdout=open(args.output / "tcpdump.log", "w"), stderr=-2)
            captures.append(capture)
            time.sleep(0.5)
        tcp_server = h1.popen(["iperf3", "-s", "-p", "5200", "-J"],
                              stdout=open(args.output / "iperf-server-tcp.log", "w"),
                              stderr=open(args.output / "iperf-server-tcp.stderr.log", "w"))
        udp_receiver = None
        servers.append(tcp_server)
        if not args.no_attack:
            udp_receiver = h1.popen([sys.executable, str(project_root / "experiments" / "udp_receiver.py"),
                                     "--port", "5201", "--duration", str(args.duration + 4),
                                     "--output", str(receiver_output)],
                                    stdout=open(args.output / "udp-receiver.log", "w"), stderr=-2)
            servers.append(udp_receiver)
        time.sleep(1)
        # Start the measured TCP client first. Confirm the TCP connection is
        # established before any high-cardinality UDP flow arrives. The fixed
        # two-second warmup is excluded from the recorded TCP rate; baseline
        # and attack runs use the same measurement window.
        tcp_warmup_s = 2
        benign = h2.popen(["iperf3", "-c", h1.IP(), "-p", "5200", "-t",
                           str(args.duration + tcp_warmup_s), "-i", "1", "-J",
                           "--get-server-output"],
                          stdout=open(args.output / "iperf-benign.json", "w"),
                          stderr=open(args.output / "iperf-benign.stderr.log", "w"))
        clients.append(benign)
        warmup_deadline = time.monotonic() + tcp_warmup_s
        established = False
        while time.monotonic() < warmup_deadline:
            if benign.poll() is not None:
                reason = (f"benign iperf3 client exited during TCP warmup "
                          f"(code {benign.returncode}); see iperf-benign.stderr.log")
                (args.output / "runner_failure.txt").write_text(reason + "\n", encoding="utf-8")
                raise RuntimeError(reason)
            if h1.cmd("ss -Htn state established '( sport = :5200 )'").strip():
                established = True
            time.sleep(0.1)
        if not established:
            reason = ("benign iperf3 TCP connection was not established within 2 seconds; "
                      "see iperf-benign.stderr.log")
            (args.output / "runner_failure.txt").write_text(reason + "\n", encoding="utf-8")
            raise RuntimeError(reason)
        if not args.no_attack:
            per_host_rate = max(1, args.udp_rate // 4)
            for name in ("a1", "a2", "a3", "a4"):
                host = net.get(name)
                sender_command = [sys.executable, str(project_root / "experiments" / "udp_sender.py"),
                                  "--target", h1.IP(), "--port", "5201", "--duration", str(args.duration),
                                  "--rate-bps", str(per_host_rate), "--output",
                                  str(args.output / f"udp-{name}.json")]
                if alias_assignments[name]:
                    sender_command.extend(["--source-file", str(args.output / f"sources-{name}.txt")])
                proc = host.popen(sender_command,
                                  stdout=open(args.output / f"udp-{name}.log", "w"), stderr=-2)
                clients.append(proc)
        if args.multi_vector:
            syn_count = args.duration * 10
            syn_client = net.get("a1").popen(
                ["hping3", "-S", "-p", "5200", "-i", "u100000", "-c",
                 str(syn_count), h1.IP()],
                stdout=open(args.output / "hping-syn.log", "w"), stderr=-2)
            icmp_client = net.get("a2").popen(
                ["ping", "-i", "0.1", "-c", str(syn_count), h1.IP()],
                stdout=open(args.output / "ping-icmp.log", "w"), stderr=-2)
            clients.extend([syn_client, icmp_client])

        start = time.time()
        while time.time() - start < args.duration:
            elapsed = round(time.time() - start, 2)
            metrics, api_rtt = controller_metrics(args.controller_url)
            row = {"elapsed_s": elapsed, "controller_api_rtt_ms": api_rtt, **metrics}
            row["ovs_flow_entries"] = 0
            row["ovs_packet_count"] = 0
            row["ovs_byte_count"] = 0
            for switch in net.switches:
                dump = switch.cmd(f"ovs-ofctl -O OpenFlow13 dump-aggregate {switch.name}")
                values = {key: int(value) for key, value in
                          re.findall(r"([a-z_]+)=(\d+)", dump)}
                row["ovs_flow_entries"] += values.get("flow_count", 0)
                row["ovs_packet_count"] += values.get("packet_count", 0)
                row["ovs_byte_count"] += values.get("byte_count", 0)
            timeline.append(row)
            print(f"PacketGuard: collected sample at {elapsed}s ({len(timeline)} total).",
                  flush=True)
            time.sleep(2)

        client_exit_codes = []
        for proc in clients:
            try:
                client_exit_codes.append(proc.wait(timeout=max(60, args.duration * 3)))
            except Exception:
                proc.terminate()
                client_exit_codes.append(None)
        if udp_receiver is not None:
            try:
                udp_receiver.wait(timeout=10)
            except Exception:
                udp_receiver.terminate()
        for proc in captures:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        for switch in net.switches:
            (args.output / f"{switch.name}-flows.txt").write_text(
                switch.cmd(f"ovs-ofctl -O OpenFlow13 dump-flows {switch.name}"), encoding="utf-8")
        with (args.output / "timeline.csv").open("w", newline="", encoding="utf-8") as f:
            fields = sorted({key for row in timeline for key in row})
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader(); writer.writerows(timeline)
        tcp_summary = iperf_summary(args.output / "iperf-benign.json",
                                    measured_from_s=float(tcp_warmup_s),
                                    measured_duration_s=float(args.duration))
        attack_hosts = {name: net.get(name).IP() for name in ("a1", "a2", "a3", "a4")}
        udp_summaries = {} if args.no_attack else udp_receiver_summary(receiver_output, attack_hosts)
        sender_summaries = {} if args.no_attack else {
            name: udp_sender_summary(args.output / f"udp-{name}.json") for name in attack_hosts}
        latest_controller, _ = controller_metrics(args.controller_url)
        failure_reasons = []
        if not tcp_summary.get("available"):
            failure_reasons.append("benign iperf3 JSON missing or invalid")
        if not timeline:
            failure_reasons.append("no controller/OVS timeline samples")
        if not latest_controller:
            failure_reasons.append("controller REST endpoint did not respond")
        if args.setup and latest_controller.get("rule_mode") != args.setup:
            failure_reasons.append("controller mode mismatch: expected %s, got %s" %
                                   (args.setup, latest_controller.get("rule_mode")))
        if any(code != 0 for code in client_exit_codes):
            failure_reasons.append(f"traffic client exit codes: {client_exit_codes}")
        if not args.no_attack:
            if any(not payload.get("available") for payload in sender_summaries.values()):
                failure_reasons.append("one or more UDP sender records missing or invalid")
            if any(not payload.get("available") for payload in udp_summaries.values()):
                failure_reasons.append("UDP receiver record missing or invalid")
        completed = not failure_reasons
        (args.output / "iperf_summary.json").write_text(json.dumps({
            "scope": "live Mininet TCP iperf3 and server-observed UDP output",
            "benign_tcp": tcp_summary, "udp_clients": udp_summaries,
            "udp_senders": sender_summaries,
            "udp_sources": json.loads(receiver_output.read_text(encoding="utf-8")).get("sources", {}) if receiver_output.exists() else {}}, indent=2), encoding="utf-8")
        (args.output / "run_metadata.json").write_text(json.dumps({
            "scope": "live Mininet/OVS testbed; isolated private topology",
            "setup": args.setup or latest_controller.get("rule_mode", "unknown"),
            "duration_s": args.duration, "aggregate_udp_rate_bps": args.udp_rate,
            "attack_enabled": not args.no_attack, "source_count": args.source_count or 4,
            "attack_prefix": str(alias_network) if alias_network else None,
            "alias_address_prefixlen": 32 if alias_network else None,
            "alias_assignments": alias_assignments,
            "multi_vector": args.multi_vector, "spoofing": False,
            "pcap_capture": str(pcap_path) if args.capture_pcap else None,
            "host_count": 16, "switch_count": 4,
            "topology": "4-switch tree; 12 benign + 4 reserved attack hosts",
            "rule_mode": latest_controller.get("rule_mode", "unknown"),
            "controller_url": args.controller_url, "samples": len(timeline),
            "benign_tcp_warmup_s": tcp_warmup_s,
            "benign_tcp_receiver_source": "iperf3 server_output_json intervals",
            "client_exit_codes": client_exit_codes, "completed": completed,
            "failure_reasons": failure_reasons,
            "note": "Raw controller/OVS timeline and client outputs are retained for this run."},
            indent=2), encoding="utf-8")
        info(f"\nPacketGuard run artifacts saved in {args.output}\n")
        if not completed:
            raise RuntimeError("; ".join(failure_reasons))
    except Exception as exc:
        # Preserve the actual startup or runtime failure even when execution
        # stops before normal result files can be written.
        failure_path = args.output / "runner_failure.txt"
        if not failure_path.exists():
            failure_path.write_text(f"{type(exc).__name__}: {exc}\n", encoding="utf-8")
        raise
    finally:
        for proc in clients + servers + captures:
            if proc.poll() is None:
                proc.terminate()
        net.stop()


if __name__ == "__main__":
    main()









