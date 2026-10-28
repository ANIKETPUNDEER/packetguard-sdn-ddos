# PacketGuard measured comparison

Completed runs: 20; failed runs: 0.

Values are mean ± sample SD from completed runs only.

| Setup | n | Benign TCP Mbps | Retention | Attack delivered Mbps | Max OVS flows | Packet-In/s |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 5 | 19.03 ± 0.00529 | 1 ± 0.000278 | 0 ± 0 | 4 ± 0 | 2639 ± 28.7 |
| none | 5 | 9.445 ± 0.0482 | 0.4964 ± 0.00253 | 9.971 ± 0.0131 | 4 ± 0 | 3109 ± 25.9 |
| per-flow | 5 | 16.22 ± 0.889 | 0.8523 ± 0.0467 | 1.716 ± 0.422 | 23 ± 0 | 9.778 ± 0.3 |
| intent | 5 | 16.17 ± 0.966 | 0.8496 ± 0.0508 | 2.108 ± 0.508 | 19 ± 0 | 9.996 ± 0.135 |

Failed attempts remain under `results/evidence/` with `lab.log`, `controller.log`, and any partial raw artifacts.
