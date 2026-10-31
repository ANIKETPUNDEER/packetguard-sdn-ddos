"""Measured source-scale test for PacketGuard, restricted to private Mininet hosts."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import statistics
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen

PREFIX = "10.0.8.0/21"  # aligned, disjoint from 10.0.0.0/24; provides 2,046 usable addresses.
COUNTS = (16, 64, 256, 1024)
FIELDS = ["setup", "source_count", "run", "benign_tcp_mbps", "attack_pkts_sent",
          "attack_pkts_delivered", "attack_delivered_mbps", "max_ovs_flow_entries",
          "packet_in_per_s", "controller_api_ms", "retention", "status", "attempt",
          "failure_reason", "evidence_dir"]


def as_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def timeline(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def cumulative_rate(rows: list[dict], field: str):
    points = [(as_number(row.get("elapsed_s")), as_number(row.get(field))) for row in rows]
    points = [(t, value) for t, value in points if t is not None and value is not None]
    if len(points) < 2 or points[-1][0] <= points[0][0]:
        return None
    return max(0.0, (points[-1][1] - points[0][1]) / (points[-1][0] - points[0][0]))


def mean(values):
    return statistics.mean(values) if values else None


def sd(values):
    return statistics.stdev(values) if len(values) > 1 else None


def ready(url: str, mode: str, process: subprocess.Popen, timeout_s: int) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urlopen(url, timeout=1) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if (response.status == 200 and payload.get("rule_mode") == mode
                    and (mode == "none" or payload.get("model_loaded") is True)):
                return True
        except Exception:
            pass
        time.sleep(.5)
    return False


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def derive_row(setup: str, count: int, run: int, attempt: int, directory: Path) -> dict:
    reasons = []
    metadata_path, summary_path = directory / "run_metadata.json", directory / "iperf_summary.json"
    metadata = load_json(metadata_path) if metadata_path.exists() else {}
    summary = load_json(summary_path) if summary_path.exists() else {}
    if not metadata_path.exists(): reasons.append("run_metadata.json missing")
    if not summary_path.exists(): reasons.append("iperf_summary.json missing")
    runner_failure = directory / "runner_failure.txt"
    if runner_failure.exists():
        reasons.append(runner_failure.read_text(encoding="utf-8").strip())
    if not metadata.get("completed", False): reasons.extend(metadata.get("failure_reasons") or ["lab did not complete"])
    if setup != "baseline" and metadata.get("source_count") != count:
        reasons.append("recorded alias count does not match requested source count")
    if setup != "baseline":
        if metadata.get("attack_prefix") != PREFIX:
            reasons.append(f"attack prefix mismatch: expected {PREFIX}")
        if metadata.get("alias_address_prefixlen") != 32:
            reasons.append("source aliases were not configured as /32 host addresses")
        assignments = metadata.get("alias_assignments") or {}
        addresses = [address for values in assignments.values() for address in values]
        expected_network = ipaddress.ip_network(PREFIX)
        if len(addresses) != count or len(set(addresses)) != count:
            reasons.append("recorded source alias assignments are incomplete or duplicated")
        elif any(ipaddress.ip_address(address) not in expected_network for address in addresses):
            reasons.append("recorded source alias is outside the reserved attack prefix")
    tcp = summary.get("benign_tcp", {})
    benign = as_number(tcp.get("receiver_mbps")) if tcp.get("available") else None
    sender_values = [item for item in summary.get("udp_senders", {}).values() if item.get("available")]
    received = summary.get("udp_sources", {})
    sent = sum(int(item.get("sent_packets", 0)) for item in sender_values)
    delivered = sum(int(item.get("packets", 0)) for item in received.values())
    delivered_bytes = sum(int(item.get("bytes", 0)) for item in received.values())
    durations = [as_number(item.get("duration_s")) for item in sender_values]
    durations = [value for value in durations if value and value > 0]
    delivered_mbps = delivered_bytes * 8 / mean(durations) / 1_000_000 if durations else 0.0
    samples = timeline(directory / "timeline.csv")
    flows = [as_number(row.get("ovs_flow_entries")) for row in samples]
    flows = [value for value in flows if value is not None]
    api = [as_number(row.get("controller_api_rtt_ms")) for row in samples]
    api = [value for value in api if value is not None]
    if benign is None: reasons.append("benign iperf3 result unavailable")
    if not samples: reasons.append("timeline.csv has no samples")
    if setup != "baseline" and not sender_values: reasons.append("UDP sender records unavailable")
    status = "completed" if not reasons else "failed"
    return {"setup": setup, "source_count": count, "run": run,
            "benign_tcp_mbps": benign, "attack_pkts_sent": sent,
            "attack_pkts_delivered": delivered, "attack_delivered_mbps": delivered_mbps,
            "max_ovs_flow_entries": max(flows) if flows else None,
            "packet_in_per_s": cumulative_rate(samples, "packet_in"),
            "controller_api_ms": mean(api), "retention": None, "status": status,
            "attempt": attempt, "failure_reason": "; ".join(dict.fromkeys(reasons)),
            "evidence_dir": str(directory)}


def write_measurement(directory: Path, row: dict) -> None:
    (directory / "measurement.json").write_text(json.dumps(row, indent=2), encoding="utf-8")


def run_one(args, setup: str, count: int, run: int, attempt: int):
    mode = "none" if setup == "baseline" else setup
    directory = args.evidence / setup / f"sources-{count:04d}" / f"run-{run:02d}" / f"attempt-{attempt:02d}"
    directory.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update({"PACKETGUARD_RULE_MODE": mode, "PACKETGUARD_ATTACK_PREFIX": PREFIX,
                "PACKETGUARD_MODEL": str((args.project / "artifacts/model.joblib").resolve())})
    controller_log = (directory / "controller.log").open("w", encoding="utf-8")
    lab_log = (directory / "lab.log").open("w", encoding="utf-8")
    controller = None
    exit_code = 1
    try:
        # A failed high-cardinality Mininet run can leave OVS namespaces or
        # bridges behind. Clean only Mininet-created state before every fresh
        # attempt so one failure cannot poison the next measurement.
        cleanup = ["mn", "-c"]
        if not args.no_sudo:
            cleanup = ["sudo", "-n", *cleanup]
        cleanup_code = subprocess.run(cleanup, cwd=args.project, stdout=lab_log,
                                      stderr=subprocess.STDOUT, check=False).returncode
        if cleanup_code != 0:
            reason = f"Mininet cleanup failed before run (exit code {cleanup_code})"
            (directory / "runner_failure.txt").write_text(reason + "\n", encoding="utf-8")
            row = derive_row(setup, count, run, attempt, directory)
            row.update(status="failed", failure_reason=reason)
            write_measurement(directory, row)
            return row, exit_code
        controller = subprocess.Popen([str(args.ryu_manager), "--ofp-tcp-listen-port", "6653",
                                       "controller/packetguard_ryu.py"], cwd=args.project, env=env,
                                      stdout=controller_log, stderr=subprocess.STDOUT)
        if not ready(args.controller_url, mode, controller, args.controller_timeout):
            reason = ("controller did not confirm requested mode with model_loaded=true"
                      if mode != "none" else "controller did not confirm forwarding-only baseline mode")
            (directory / "runner_failure.txt").write_text(reason + "\n", encoding="utf-8")
            row = derive_row(setup, count, run, attempt, directory)
            row.update(status="failed", failure_reason=reason)
            write_measurement(directory, row)
            return row, exit_code
        command = [str(args.lab_python), "experiments/run_lab.py", "--duration", str(args.duration),
                   "--udp-rate", "10M", "--setup", mode, "--output", str(directory),
                   "--controller-url", args.controller_url]
        if setup == "baseline":
            command.append("--no-attack")
        else:
            command.extend(["--source-count", str(count), "--attack-prefix", PREFIX])
        if not args.no_sudo:
            command = ["sudo", "-n", *command]
        exit_code = subprocess.run(command, cwd=args.project, stdout=lab_log,
                                   stderr=subprocess.STDOUT, check=False).returncode
    finally:
        stop(controller); controller_log.close(); lab_log.close()
    row = derive_row(setup, count, run, attempt, directory)
    if exit_code != 0 and not row["failure_reason"]:
        row.update(status="failed", failure_reason=f"lab process exited with code {exit_code}")
    write_measurement(directory, row)
    return row, exit_code


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS); writer.writeheader(); writer.writerows(rows)


def previous_row_uses_current_aliases(row: dict) -> bool:
    """Do not resume measurements made with the old overlapping source pool."""
    if row.get("setup") == "baseline":
        return True
    directory = Path(row.get("evidence_dir", ""))
    metadata_path = directory / "run_metadata.json"
    if not metadata_path.exists():
        return False
    try:
        metadata = load_json(metadata_path)
        count = int(row.get("source_count", -1))
        assignments = metadata.get("alias_assignments") or {}
        addresses = [address for values in assignments.values() for address in values]
        network = ipaddress.ip_network(PREFIX)
        return (metadata.get("attack_prefix") == PREFIX
                and metadata.get("alias_address_prefixlen") == 32
                and len(addresses) == count and len(set(addresses)) == count
                and all(ipaddress.ip_address(address) in network for address in addresses))
    except (OSError, ValueError, TypeError):
        return False


def complete(rows: list[dict], repetitions: int) -> bool:
    have = {(row.get("setup"), int(row.get("source_count", -1)), int(row.get("run", -1)))
            for row in rows if row.get("status") == "completed"}
    expected = {("baseline", 0, run) for run in range(1, repetitions + 1)}
    expected |= {(setup, count, run) for setup in ("per-flow", "intent") for count in COUNTS
                 for run in range(1, repetitions + 1)}
    return expected <= have


def remove_reports(results: Path) -> None:
    for path in (results / "scale_summary.json", results / "scale_summary.md",
                 results / "plots" / "flow_entries_vs_source_count.png"):
        if path.exists(): path.unlink()


def report(results: Path, rows: list[dict]) -> None:
    completed = [row for row in rows if row["status"] == "completed"]
    baseline = [float(row["benign_tcp_mbps"]) for row in completed if row["setup"] == "baseline"]
    baseline_mean = mean(baseline)
    for row in rows:
        value = as_number(row.get("benign_tcp_mbps"))
        row["retention"] = value / baseline_mean if baseline_mean and value is not None else None
    write_csv(results / "scale_runs.csv", rows)
    summary = {"prefix": PREFIX, "baseline_mean_mbps": baseline_mean, "groups": {}}
    for setup in ("per-flow", "intent"):
        for count in COUNTS:
            group = [row for row in completed if row["setup"] == setup and int(row["source_count"]) == count]
            metrics = {}
            for key in ("max_ovs_flow_entries", "attack_delivered_mbps", "retention", "packet_in_per_s"):
                values = [as_number(row[key]) for row in group]; values = [v for v in values if v is not None]
                metrics[key] = {"n": len(values), "mean": mean(values), "sd": sd(values)}
            summary["groups"][f"{setup}-{count}"] = metrics
    (results / "scale_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    lines = ["# PacketGuard measured source-scale test", "", "Values are mean ± sample SD from completed runs.", "",
             "| Mode | Sources | n | Max OVS flow entries | Delivered Mbps | Benign retention | PACKET_IN/s |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for setup in ("per-flow", "intent"):
        for count in COUNTS:
            item = summary["groups"][f"{setup}-{count}"]
            def show(key):
                record = item[key]
                return "—" if record["mean"] is None else (f"{record['mean']:.4g} ± {record['sd']:.3g}" if record["sd"] is not None else f"{record['mean']:.4g}")
            lines.append(f"| {setup} | {count} | {item['max_ovs_flow_entries']['n']} | {show('max_ovs_flow_entries')} | {show('attack_delivered_mbps')} | {show('retention')} | {show('packet_in_per_s')} |")
    (results / "scale_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    import matplotlib.pyplot as plt
    output = results / "plots"; output.mkdir(parents=True, exist_ok=True)
    fig, axis = plt.subplots(figsize=(7.5, 4.5))
    for setup, color in (("per-flow", "#d95f02"), ("intent", "#1b9e77")):
        xs, ys, errors = [], [], []
        for count in COUNTS:
            values = [float(row["max_ovs_flow_entries"]) for row in completed if row["setup"] == setup and int(row["source_count"]) == count and row["max_ovs_flow_entries"] not in (None, "")]
            xs.append(count); ys.append(mean(values)); errors.append(sd(values) or 0)
        axis.errorbar(xs, ys, yerr=errors, marker="o", capsize=4, label=setup, color=color)
    axis.set_xscale("log", base=2); axis.set_xticks(COUNTS); axis.set_xticklabels([str(x) for x in COUNTS])
    axis.set(xlabel="Real attack source addresses", ylabel="Maximum OVS flow entries (mean ± SD)", title="Flow-entry scaling by mitigation mode")
    axis.grid(True, alpha=.25); axis.legend(); fig.tight_layout()
    fig.savefig(output / "flow_entries_vs_source_count.png", dpi=150); plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(".")); parser.add_argument("--results", type=Path, default=Path("results/scale"))
    parser.add_argument("--duration", type=int, default=20); parser.add_argument("--repetitions", type=int, default=3); parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--ryu-manager", type=Path, default=Path(".venv/bin/ryu-manager")); parser.add_argument("--lab-python", type=Path, default=Path("/usr/bin/python3"))
    parser.add_argument("--controller-url", default="http://127.0.0.1:8080/stats/packetguard"); parser.add_argument("--controller-timeout", type=int, default=30); parser.add_argument("--no-sudo", action="store_true")
    args = parser.parse_args(); args.project = args.project.resolve(); args.results = (args.project / args.results).resolve() if not args.results.is_absolute() else args.results; args.evidence = args.results / "evidence"
    if args.duration < 5 or args.repetitions < 1 or args.max_attempts < 1: parser.error("duration must be >=5; repetitions and attempts must be positive")
    if not args.ryu_manager.is_absolute(): args.ryu_manager = args.project / args.ryu_manager
    if not args.lab_python.exists() or not args.ryu_manager.exists(): parser.error("lab Python or ryu-manager missing")
    if not args.no_sudo and subprocess.run(["sudo", "-n", "true"], check=False).returncode != 0: parser.error("run sudo -v first")
    args.results.mkdir(parents=True, exist_ok=True); args.evidence.mkdir(parents=True, exist_ok=True)
    csv_path = args.results / "scale_runs.csv"; rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8"))) if csv_path.exists() else []
    invalidated = 0
    for row in rows:
        if row.get("setup") != "baseline" and row.get("status") == "completed" and not previous_row_uses_current_aliases(row):
            row["status"] = "invalidated"
            row["failure_reason"] = "invalidated: prior source aliases overlapped the Mininet host subnet or used a subnet mask"
            evidence_dir = Path(row.get("evidence_dir", ""))
            measurement_path = evidence_dir / "measurement.json"
            if measurement_path.exists():
                try:
                    measurement = load_json(measurement_path)
                    measurement.update(status="invalidated", failure_reason=row["failure_reason"])
                    write_measurement(evidence_dir, measurement)
                except (OSError, ValueError, TypeError):
                    pass
            invalidated += 1
    if invalidated:
        write_csv(csv_path, rows)
        remove_reports(args.results)
        print(f"Invalidated {invalidated} completed attack rows made with the overlapping 10.0.0.0/21 alias pool; rerunning with {PREFIX} aliases as /32.", flush=True)
    jobs = [("baseline", 0)] + [(mode, count) for mode in ("per-flow", "intent") for count in COUNTS]
    for setup, count in jobs:
        for run in range(1, args.repetitions + 1):
            if any(row.get("setup") == setup and int(row.get("source_count", -1)) == count and int(row.get("run", -1)) == run and row.get("status") == "completed" for row in rows): continue
            root = args.evidence / setup / f"sources-{count:04d}" / f"run-{run:02d}"
            existing = [int(p.name.split("-")[-1]) for p in root.glob("attempt-*") if p.is_dir() and p.name.split("-")[-1].isdigit()] if root.exists() else []
            final = None
            for attempt in range(max(existing, default=0) + 1, max(existing, default=0) + 1 + args.max_attempts):
                print(f"Running {setup}, sources={count}, repetition={run}, attempt={attempt}", flush=True)
                final, code = run_one(args, setup, count, run, attempt)
                if final["status"] == "completed" and code == 0: break
                print(f"Attempt failed: {final['failure_reason'] or 'see evidence logs'}", flush=True)
            rows = [row for row in rows if not (row.get("setup") == setup and int(row.get("source_count", -1)) == count and int(row.get("run", -1)) == run)] + [final]
            write_csv(csv_path, rows)
    if not complete(rows, args.repetitions):
        remove_reports(args.results); print("Scale test incomplete: evidence and scale_runs.csv were kept; no summary or plot was written.", flush=True); raise SystemExit(2)
    report(args.results, rows); print(f"Scale test written to {args.results}", flush=True)


if __name__ == "__main__": main()

