# PacketGuard

PacketGuard includes both a reproducible software simulation and a Linux SDN lab implementation: a Mininet topology, a Ryu/OpenFlow 1.3 controller, a Random Forest training pipeline, graduated mitigation, and experiment scripts.

**Scope:** the Windows workspace cannot run Mininet/OVS/Ryu. The project was exercised in an isolated WSL Mininet testbed; retain its raw artifacts separately from the synthetic simulator output. The standalone simulator uses synthetic flows and does not use CIC-DDoS2019. Its results are not real-network measurements.

## Quick software simulation

- Python 3.10 or newer
- No third-party packages required

## Run

From this directory:

```powershell
python run.py --seed 7 --output results
```

The command runs a dependency-free demo and writes synthetic results. For the actual SDN lab, use the separate instructions below.

## Linux SDN lab (Ryu + Mininet + OVS)

Use the Mininet VM or a dedicated Ubuntu 20.04 / Python 3.8 environment where Mininet and Open vSwitch are supported. The Ryu 4.34 upstream project is currently marked unmaintained, so this project keeps Ryu to match the course review stack and pins the legacy controller version; use a disposable lab VM and expect dependency compatibility work if you use a newer Python. The controller and topology source lives in `controller/`, `topology/`, and `experiments/`.

1. Install the system packages and Python dependencies:

   ```bash
   sudo apt update
   sudo apt install -y mininet openvswitch-switch iperf3 hping3 tcpdump python3.8-venv
   sudo systemctl enable --now openvswitch-switch
   python3.8 -m venv .venv
   . .venv/bin/activate
   pip install -r requirements-sdn.txt
   ```

2. Train and evaluate the classifier from the included compact, feature-selected CIC-DDoS2019 derivative:

   ```bash
   python ml/train_model.py --dataset data/CIC-DDoS2019-15C-test.csv --output artifacts
   ```

   This 9.49 MB subset omits protocol and destination port; the loader sets those fields to zero, so the resulting model relies on traffic statistics. See `data/README.md` for its source and limitations. If protocol/port learning is required, get the full CIC-DDoS2019 CICFlowMeter CSV files from the publisher and keep them under `data/`. Train from the full data with:

   ```bash
   python ml/train_model.py --dataset data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --output artifacts
   ```

   The loader maps CICFlowMeter fields into the project's five features: packet rate, estimated forward bytes per two-second window, capped window duration, protocol number, and destination port. Labels are reduced to benign/attack. It writes a stratified 75/25 holdout evaluation, five-fold CV on the training split, threshold sweep, feature importances, ROC/PR metrics, and `artifacts/evaluation_curves.png`. Inspect the evaluation and class balance before using a model; the window conversion is an approximation because CIC rows summarize whole flows.

3. Start the controller in one terminal from this directory:

   ```bash
   . .venv/bin/activate
   ryu-manager --ofp-tcp-listen-port 6653 controller/packetguard_ryu.py
   ```

   The controller expects `artifacts/model.joblib`. It polls flow stats every 2 seconds, extracts deltas, scores flows, and exports counters at `http://127.0.0.1:8080/stats/packetguard`.

   The default `PACKETGUARD_RULE_MODE=intent` groups the reserved attack prefix by protocol and destination port. To compare with per-flow rules, stop the controller and restart it with:

   ```bash
   PACKETGUARD_RULE_MODE=per-flow ryu-manager --ofp-tcp-listen-port 6653 controller/packetguard_ryu.py
   ```

   Run metadata records the selected mode.

4. In a second terminal, start the live Matplotlib dashboard:

   ```bash
   python experiments/live_dashboard.py
   ```

5. In a third terminal, run the bounded 4-switch / 16-host lab experiment:

   ```bash
   sudo .venv/bin/python experiments/run_lab.py --duration 20 --udp-rate 1M
   ```

   This launches Mininet, starts one benign TCP iperf flow and four bounded UDP clients, samples controller/OVS counters, writes results, and then shuts the topology down. For an interactive Mininet CLI instead, run `sudo .venv/bin/python topology/packetguard_topo.py`; then run `pingall` there.

   Add `--multi-vector` to include low-rate TCP SYN and ICMP probes from two other Mininet attack hosts. Add `--capture-pcap` to capture the run at h1 for later CICFlowMeter conversion. All traffic is restricted to private Mininet hosts; the script does not spoof source addresses and caps UDP at 10 Mbps. Four attack hosts check the control path but do not reproduce the review's 1,024-source scale claim; use the software simulation for controlled rule-count scaling. Do not adapt lab traffic to external or production systems.

6. Generate plots from the collected run:

   ```bash
   python experiments/plot_results.py --input results/live --output results/live/plots
   ```

OpenFlow wildcard aggregation is scoped to the reserved attacker prefix `10.0.0.192/28`; legitimate test hosts use other addresses. This explicit lab assumption prevents the aggregate rule from unintentionally matching the legitimate hosts. A deployment must derive and validate attack scopes for its own network.

To evaluate CIC data together with captured Mininet traffic, convert the PCAP with CICFlowMeter, then pass its flow CSV alongside the CIC CSV using multiple `--dataset` arguments. Record which run produced each input file; the trainer concatenates the supplied rows and reports the source filenames.

## Measured comparison: none vs per-flow vs intent

Use WSL for this experiment. It runs five repetitions for each attack setup plus five no-attack benign TCP baselines. Each repetition starts a fresh controller and uses a bounded 20-second, 10 Mbps aggregate UDP load only between private Mininet hosts. No source address spoofing is used.

First copy the changed files from the Windows project to the WSL checkout, then run the comparison from `~/packetguard`:

```bash
sudo -v
source .venv/bin/activate
python experiments/compare_setups.py --duration 20 --repetitions 5 --max-attempts 2
```

The command writes `results/runs.csv`, raw files under `results/evidence/<setup>/run-XX/attempt-XX/`, `results/comparison_summary.{json,md}`, and plots under `results/plots/`. Failed attempts are retained with controller and lab logs; only rows marked `completed` contribute to mean ± sample SD summaries. `baseline` uses `none` mode without attack traffic. `none` with attack traffic is a learning-switch control with no model, meter, or mitigation rule; `per-flow` and `intent` use the trained model.
## Outputs

The simulator command writes:

- `results/metrics.json` — classifier and mitigation metrics, with scope metadata
- `results/flows.csv` — per-flow synthetic inputs, predictions, and actions
- `results/rule_counts.csv` — rule counts over simulated time
- `results/report.md` — a concise generated results report

The live-lab script writes separate Ryu/OVS observations, iperf3 JSON, flow dumps, and run metadata under `results/live/`. Never combine synthetic simulation output with live testbed measurements.

Use `--samples` to change the generated dataset size. Reusing a seed reproduces the same dataset and results.

## Project layout

- `packetguard/data.py` — synthetic flow generation and deterministic train/test split
- `packetguard/forest.py` — dependency-free Random Forest classifier
- `packetguard/policy.py` — graduated mitigation and intent aggregation
- `packetguard/simulation.py` — attack scenario and flow-table comparison
- `packetguard/reporting.py` — CSV, JSON, and Markdown output
- `run.py` — command-line entry point
- `ml/train_model.py` — CICFlowMeter CSV loader, split, training, and evaluation
- `controller/packetguard_ryu.py` — Ryu OpenFlow 1.3 app, telemetry polling, meter and rule installation
- `topology/packetguard_topo.py` — custom 4-switch tree with 12 benign and 4 reserved attack hosts
- `experiments/` — bounded Mininet traffic scenario, metrics collection, and plots

## What the standalone simulation models

Each record represents a flow with packet rate, byte count, duration, protocol, and destination port. Labels are benign, UDP flood, SYN flood, or ICMP flood. Synthetic class distributions overlap to make classification imperfect. A separate generated scenario creates many attacker source addresses and a smaller benign population. The baseline installs one rule per attacker source; the proposed policy groups matching attack intent into a bounded set of rules.

The simulator's rule counts, rates, and classifier scores describe only this software model. They are not equivalent to OpenFlow switch counters, controller RTT, real packet throughput, or generalization to CIC-DDoS2019. Use the Linux SDN lab for real testbed data.

## Remaining real-testbed work

1. Run the Linux setup and resolve any platform-specific compatibility issues.
2. Confirm the CICFlowMeter CSV columns and label balance in the downloaded release.
3. Compare live controller feature distributions with training data before interpreting model predictions.
4. Repeat controlled runs and report measured switch/controller counters separately from simulation output.

## Safety

The included traffic driver is bounded and only targets the private Mininet lab hosts. It sends no forged source addresses and must remain isolated from public/production systems.

