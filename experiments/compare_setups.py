"""Run measured PacketGuard setup comparisons in the isolated Mininet lab.

Run from a WSL project checkout after ``sudo -v``. The command starts a fresh
Ryu controller for every repetition, retaining raw artifacts for each attempt.
It never fabricates a missing measurement: incomplete attempts are preserved
and reported as failed rather than included in the summaries.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

FIELDS = [
    "setup", "run", "benign_tcp_mbps", "attack_pkts_sent",
    "attack_pkts_delivered", "attack_delivered_mbps", "max_ovs_flow_entries",
    "first_mitigation_s", "packet_in_per_s", "controller_api_ms", "retention",
    "status", "attempt", "failure_reason", "evidence_dir",
]


def get_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def number(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def mean(values: list[float]) -> float | None:
    return statistics.mean(values) if values else None


def sample_sd(values: list[float]) -> float | None:
    return statistics.stdev(values) if len(values) > 1 else None


def read_timeline(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def rate_from_cumulative(rows: list[dict], field: str) -> float | None:
    points = [(number(row.get("elapsed_s")), number(row.get(field))) for row in rows]
    points = [(t, v) for t, v in points if t is not None and v is not None]
    if len(points) < 2:
        return None
    start_t, start_v = points[0]
    end_t, end_v = points[-1]
    if end_t <= start_t:
        return None
    return max(0.0, (end_v - start_v) / (end_t - start_t))


def row_from_evidence(setup: str, run: int, attempt: int, run_dir: Path) -> dict:
    metadata_path = run_dir / "run_metadata.json"
    summary_path = run_dir / "iperf_summary.json"
    metadata = get_json(metadata_path) if metadata_path.exists() else {}
    summary = get_json(summary_path) if summary_path.exists() else {}
    rows = read_timeline(run_dir / "timeline.csv")
    reasons = list(metadata.get("failure_reasons") or [])
    if not metadata_path.exists():
        reasons.append("run_metadata.json missing")
    if not summary_path.exists():
        reasons.append("iperf_summary.json missing")
    if metadata.get("setup") != ("none" if setup == "baseline" else setup):
        reasons.append("recorded controller setup does not match requested setup")
    if not metadata.get("completed", False):
        if not reasons:
            reasons.append("lab run did not mark itself completed")
    tcp = summary.get("benign_tcp", {})
    benign = number(tcp.get("receiver_mbps")) if tcp.get("available") else None
    senders = summary.get("udp_senders", {})
    receivers = summary.get("udp_clients", {})
    attack_sent = sum(int(item.get("sent_packets", 0)) for item in senders.values()
                      if item.get("available"))
    attack_delivered = sum(int(item.get("packets", 0)) for item in receivers.values()
                           if item.get("available"))
    delivered_bytes = sum(int(item.get("bytes", 0)) for item in receivers.values()
                          if item.get("available"))
    sender_durations = [number(item.get("duration_s")) for item in senders.values()
                        if item.get("available")]
    sender_durations = [value for value in sender_durations if value and value > 0]
    delivered_mbps = (delivered_bytes * 8 / statistics.mean(sender_durations) / 1_000_000
                      if sender_durations else 0.0)
    if setup == "baseline":
        attack_sent = attack_delivered = 0
        delivered_mbps = 0.0
    mitigation = [number(row.get("mitigation_rules_installed")) for row in rows]
    first_mitigation = None
    for sample, installed in zip(rows, mitigation):
        if installed is not None and installed > 0:
            first_mitigation = number(sample.get("elapsed_s"))
            break
    api_values = [number(row.get("controller_api_rtt_ms")) for row in rows]
    api_values = [value for value in api_values if value is not None]
    flow_entries = [number(row.get("ovs_flow_entries")) for row in rows]
    flow_entries = [value for value in flow_entries if value is not None]
    status = "completed" if not reasons and benign is not None else "failed"
    return {
        "setup": setup, "run": run, "benign_tcp_mbps": benign,
        "attack_pkts_sent": attack_sent, "attack_pkts_delivered": attack_delivered,
        "attack_delivered_mbps": delivered_mbps,
        "max_ovs_flow_entries": max(flow_entries) if flow_entries else None,
        "first_mitigation_s": first_mitigation,
        "packet_in_per_s": rate_from_cumulative(rows, "packet_in"),
        "controller_api_ms": mean(api_values), "retention": None,
        "status": status, "attempt": attempt, "failure_reason": "; ".join(reasons),
        "evidence_dir": str(run_dir),
    }


def write_measurement(run_dir: Path, row: dict) -> None:
    """Persist the derived row beside the raw JSON, logs, and timeline."""
    (run_dir / "measurement.json").write_text(json.dumps(row, indent=2), encoding="utf-8")

def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def controller_ready(url: str, expected_mode: str, require_model: bool, process: subprocess.Popen, timeout_s: int) -> bool:
    """Require the newly started process and its requested mode, not a stale API."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urlopen(url, timeout=1) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if (response.status == 200 and payload.get("rule_mode") == expected_mode
                    and (not require_model or payload.get("model_loaded") is True)):
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_one(args: argparse.Namespace, setup: str, run: int, attempt: int) -> tuple[dict, int]:
    actual_mode = "none" if setup == "baseline" else setup
    run_dir = args.evidence / setup / f"run-{run:02d}" / f"attempt-{attempt:02d}"
    run_dir.mkdir(parents=True, exist_ok=False)
    controller_log = (run_dir / "controller.log").open("w", encoding="utf-8")
    lab_log = (run_dir / "lab.log").open("w", encoding="utf-8")
    env = os.environ.copy()
    env["PACKETGUARD_RULE_MODE"] = actual_mode
    env["PACKETGUARD_MODEL"] = str((args.project / "artifacts" / "model.joblib").resolve())
    controller = None
    exit_code = 1
    try:
        controller = subprocess.Popen(
            [str(args.ryu_manager), "--ofp-tcp-listen-port", "6653",
             "controller/packetguard_ryu.py"], cwd=args.project, env=env,
            stdout=controller_log, stderr=subprocess.STDOUT)
        if not controller_ready(args.controller_url, actual_mode, actual_mode != "none", controller, args.controller_timeout):
            reason = ("Ryu did not confirm the requested mode and model_loaded=true before the timeout"
                      if actual_mode != "none" else "Ryu REST API did not become ready in forwarding-only mode")
            (run_dir / "runner_failure.txt").write_text(reason + ".\n", encoding="utf-8")
            row = row_from_evidence(setup, run, attempt, run_dir)
            row["status"] = "failed"
            row["failure_reason"] = reason
            write_measurement(run_dir, row)
            return row, exit_code
        command = [str(args.lab_python), "experiments/run_lab.py", "--duration", str(args.duration),
                   "--udp-rate", "10M", "--setup", actual_mode, "--output", str(run_dir),
                   "--controller-url", args.controller_url]
        if setup == "baseline":
            command.append("--no-attack")
        if not args.no_sudo:
            command = ["sudo", "-n", *command]
        completed = subprocess.run(command, cwd=args.project, stdout=lab_log,
                                   stderr=subprocess.STDOUT, check=False)
        exit_code = completed.returncode
    finally:
        stop_process(controller)
        controller_log.close()
        lab_log.close()
    row = row_from_evidence(setup, run, attempt, run_dir)
    if exit_code != 0 and not row["failure_reason"]:
        row["failure_reason"] = f"lab process exited with code {exit_code}"
        row["status"] = "failed"
    write_measurement(run_dir, row)
    return row, exit_code


def generate_report(results_dir: Path, rows: list[dict]) -> None:
    completed = [row for row in rows if row["status"] == "completed"]
    baselines = [float(row["benign_tcp_mbps"]) for row in completed
                 if row["setup"] == "baseline" and row["benign_tcp_mbps"] is not None]
    baseline_mean = mean(baselines)
    for row in rows:
        value = number(row.get("benign_tcp_mbps"))
        row["retention"] = value / baseline_mean if baseline_mean and value is not None else None
    write_csv(results_dir / "runs.csv", rows)
    setups = ["baseline", "none", "per-flow", "intent"]
    metrics = ["benign_tcp_mbps", "retention", "attack_delivered_mbps",
               "max_ovs_flow_entries", "packet_in_per_s", "controller_api_ms"]
    summary = {"baseline_mean_mbps": baseline_mean, "completed_runs": len(completed),
               "failed_runs": len(rows) - len(completed), "setups": {}}
    for setup in setups:
        subset = [row for row in completed if row["setup"] == setup]
        item = {"n": len(subset)}
        for metric in metrics:
            values = [number(row.get(metric)) for row in subset]
            values = [value for value in values if value is not None]
            item[metric] = {"mean": mean(values), "sd": sample_sd(values), "n": len(values)}
        summary["setups"][setup] = item
    (results_dir / "comparison_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    lines = ["# PacketGuard measured comparison", "",
             f"Completed runs: {summary['completed_runs']}; failed runs: {summary['failed_runs']}.", "",
             "Values are mean ± sample SD from completed runs only.", "",
             "| Setup | n | Benign TCP Mbps | Retention | Attack delivered Mbps | Max OVS flows | Packet-In/s |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for setup in setups:
        item = summary["setups"][setup]
        def show(metric: str) -> str:
            record = item[metric]
            if record["mean"] is None:
                return "—"
            return f"{record['mean']:.4g} ± {record['sd']:.3g}" if record["sd"] is not None else f"{record['mean']:.4g}"
        lines.append("| %s | %d | %s | %s | %s | %s | %s |" %
                     (setup, item["n"], show("benign_tcp_mbps"), show("retention"),
                      show("attack_delivered_mbps"), show("max_ovs_flow_entries"),
                      show("packet_in_per_s")))
    lines.extend(["", "Failed attempts remain under `results/evidence/` with `lab.log`, "
                  "`controller.log`, and any partial raw artifacts."])
    (results_dir / "comparison_summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    plot_comparison(results_dir / "runs.csv", results_dir / "plots")


def plot_comparison(csv_path: Path, output: Path) -> None:
    import matplotlib.pyplot as plt
    output.mkdir(parents=True, exist_ok=True)
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row.get("status") == "completed"]
    for metric, label, filename in [
        ("retention", "Benign TCP retention", "benign_retention.png"),
        ("attack_delivered_mbps", "Attack traffic delivered (Mbps)", "attack_delivered.png"),
        ("max_ovs_flow_entries", "Maximum OVS flow entries", "flow_entries.png"),
        ("packet_in_per_s", "Controller Packet-In rate (events/s)", "packet_in_rate.png"),
    ]:
        groups = [(setup, [float(row[metric]) for row in rows
                           if row["setup"] == setup and row.get(metric) not in ("", None)])
                  for setup in ("baseline", "none", "per-flow", "intent")]
        groups = [(setup, values) for setup, values in groups if values]
        if not groups:
            continue
        names, values = zip(*groups)
        averages = [statistics.mean(item) for item in values]
        errors = [statistics.stdev(item) if len(item) > 1 else 0 for item in values]
        fig, axis = plt.subplots(figsize=(7.5, 4.5))
        axis.bar(names, averages, yerr=errors, capsize=5, color="#3a86c8")
        axis.set(title=label, ylabel=label + " (mean ± SD)", xlabel="Setup")
        axis.grid(axis="y", alpha=.25)
        fig.tight_layout()
        fig.savefig(output / filename, dpi=150)
        plt.close(fig)


def requested_runs_complete(rows: list[dict], repetitions: int) -> bool:
    completed = {(row.get("setup"), str(row.get("run"))) for row in rows
                 if row.get("status") == "completed"}
    expected = {(setup, str(run)) for setup in ("baseline", "none", "per-flow", "intent")
                for run in range(1, repetitions + 1)}
    return expected.issubset(completed)


def remove_partial_reports(results_dir: Path) -> None:
    """Remove stale comparison conclusions when a requested run has failed."""
    for name in ("comparison_summary.json", "comparison_summary.md"):
        path = results_dir / name
        if path.exists():
            path.unlink()
    plots = results_dir / "plots"
    for name in ("benign_retention.png", "attack_delivered.png", "flow_entries.png",
                 "packet_in_rate.png"):
        path = plots / name
        if path.exists():
            path.unlink()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path("."))
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--ryu-manager", type=Path, default=Path(".venv/bin/ryu-manager"))
    parser.add_argument("--lab-python", type=Path, default=Path("/usr/bin/python3"))
    parser.add_argument("--controller-url", default="http://127.0.0.1:8080/stats/packetguard")
    parser.add_argument("--controller-timeout", type=int, default=30)
    parser.add_argument("--no-sudo", action="store_true")
    args = parser.parse_args()
    args.project = args.project.resolve()
    args.results = (args.project / args.results).resolve() if not args.results.is_absolute() else args.results
    args.evidence = args.results / "evidence"
    if args.duration < 5 or args.repetitions < 1 or args.max_attempts < 1:
        parser.error("duration must be >= 5; repetitions and max-attempts must be positive")
    if not args.ryu_manager.is_absolute():
        args.ryu_manager = args.project / args.ryu_manager
    if not args.lab_python.exists() or not args.ryu_manager.exists():
        parser.error("lab Python or ryu-manager path does not exist; activate the documented WSL environment")
    if not args.no_sudo:
        privilege = subprocess.run(["sudo", "-n", "true"], check=False)
        if privilege.returncode != 0:
            parser.error("run `sudo -v` once, then rerun this command so bounded Mininet runs can start")
    args.results.mkdir(parents=True, exist_ok=True)
    args.evidence.mkdir(parents=True, exist_ok=True)
    output_csv = args.results / "runs.csv"
    rows: list[dict] = []
    if output_csv.exists():
        with output_csv.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    done = {(row["setup"], int(row["run"])) for row in rows if row.get("status") == "completed"}
    for setup in ("baseline", "none", "per-flow", "intent"):
        for run in range(1, args.repetitions + 1):
            if (setup, run) in done:
                print(f"Skipping completed {setup} run {run}", flush=True)
                continue
            final_row = None
            attempt_root = args.evidence / setup / f"run-{run:02d}"
            prior_attempts = [int(path.name.split("-")[-1]) for path in attempt_root.glob("attempt-*")
                              if path.is_dir() and path.name.split("-")[-1].isdigit()] if attempt_root.exists() else []
            first_attempt = max(prior_attempts, default=0) + 1
            for attempt in range(first_attempt, first_attempt + args.max_attempts):
                print(f"Running {setup} repetition {run}, attempt {attempt}", flush=True)
                row, code = run_one(args, setup, run, attempt)
                final_row = row
                if row["status"] == "completed" and code == 0:
                    break
                print(f"Attempt failed: {row['failure_reason'] or 'see lab.log'}", flush=True)
            rows = [row for row in rows if not (row["setup"] == setup and int(row["run"]) == run)]
            rows.append(final_row)
            write_csv(output_csv, rows)
    if not requested_runs_complete(rows, args.repetitions):
        remove_partial_reports(args.results)
        successful = sum(row.get("status") == "completed" for row in rows)
        expected = 4 * args.repetitions
        print(f"Comparison incomplete: {successful}/{expected} requested runs completed. "
              "runs.csv and evidence were kept; no summary or plots were written.", flush=True)
        raise SystemExit(2)
    generate_report(args.results, rows)
    print(f"Measured comparison written to {args.results}", flush=True)


if __name__ == "__main__":
    main()






