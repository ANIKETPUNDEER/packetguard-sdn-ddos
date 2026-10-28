"""Train/evaluate a Random Forest from CICFlowMeter or CIC-DDoS2019-15C CSVs.

For CICFlowMeter inputs, required columns are Flow Duration, Total Fwd Packets,
Total Length of Fwd Packets, Protocol, Destination Port, and Label. The compact
CIC-DDoS2019-15C variant is also supported; its omitted protocol/port features
are filled with zero, so that model learns to rely on its remaining features.
The input CSV is not modified. Data files are not included in this repository.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

FEATURES = ["packet_rate", "byte_count", "duration_s", "protocol", "dst_port"]
REQUIRED = {"flow duration", "label"}


def load_cic_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)
    original = list(df.columns)
    normalized = {str(c).strip().lstrip("\ufeff").casefold(): c for c in original}
    missing = sorted(REQUIRED - set(normalized))
    if missing:
        raise ValueError(f"Missing CICFlowMeter columns: {missing}; found {original}")
    def col(name): return normalized[name]
    duration_us = pd.to_numeric(df[col("flow duration")], errors="coerce")
    if {"total fwd packets", "total length of fwd packets", "protocol", "destination port"} <= set(normalized):
        fwd_packets = pd.to_numeric(df[col("total fwd packets")], errors="coerce")
        fwd_bytes = pd.to_numeric(df[col("total length of fwd packets")], errors="coerce")
        proto = pd.to_numeric(df[col("protocol")], errors="coerce")
        dst_port = pd.to_numeric(df[col("destination port")], errors="coerce")
        packet_rate_source = None
    elif {"flow packets/s", "subflow fwd bytes"} <= set(normalized):
        # Compact CIC-DDoS2019-15C omits protocol and destination port. Keep
        # the controller's five-column model interface but train with these
        # two fields fixed at zero; runtime scores then depend on traffic stats.
        packet_rate_source = pd.to_numeric(df[col("flow packets/s")], errors="coerce")
        fwd_bytes = pd.to_numeric(df[col("subflow fwd bytes")], errors="coerce")
        fwd_packets = None
        proto = pd.Series(0.0, index=df.index)
        dst_port = pd.Series(0.0, index=df.index)
    else:
        raise ValueError("CSV must contain CICFlowMeter features or the compact "
                         "CIC-DDoS2019-15C fields Flow Packets/s and Subflow Fwd Bytes")
    raw_labels = df[col("label")]
    labels = raw_labels.astype(str).str.strip().str.casefold()
    # Collapse attack families to a binary label. This is intentional: the
    # controller's intent key uses observed protocol and destination port.
    y = labels.map(lambda label: "benign" if label in {"benign", "normal"} else "attack")
    flow_duration_s = duration_us.clip(lower=1) / 1_000_000.0
    if fwd_packets is not None:
        fwd_packets = fwd_packets.clip(lower=0)
    fwd_bytes = fwd_bytes.clip(lower=0)
    # Controller features represent successive two-second stats windows.
    # CIC rows summarize whole flows, so approximate the window byte count
    # from the flow's average rate and cap duration to the polling interval.
    window_s = flow_duration_s.clip(upper=2.0)
    packet_rate = (packet_rate_source if packet_rate_source is not None
                   else fwd_packets / flow_duration_s)
    window_bytes = (fwd_bytes / flow_duration_s) * window_s
    out = pd.DataFrame({"packet_rate": packet_rate, "byte_count": window_bytes,
                        "duration_s": window_s, "protocol": proto,
                        "dst_port": dst_port, "label": y})
    out.replace([float("inf"), -float("inf")], np.nan, inplace=True)
    out.dropna(subset=FEATURES + ["label"], inplace=True)
    out = out[raw_labels.loc[out.index].notna()]
    for feature in ("protocol", "dst_port"):
        out[feature] = out[feature].clip(lower=0, upper=65535)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, nargs="+", type=Path,
                        help="one or more CICFlowMeter CSVs; keep source datasets out of Git")
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--cv-folds", type=int, default=5,
                        help="stratified CV folds on the training split; use 0 to skip")
    parser.add_argument("--cv-max-rows", type=int, default=30000,
                        help="cap CV workload using a seeded stratified training sample")
    args = parser.parse_args()
    if args.trees < 1:
        parser.error("--trees must be positive")
    if args.cv_max_rows < 1:
        parser.error("--cv-max-rows must be positive")
    missing_files = [str(path) for path in args.dataset if not path.is_file()]
    if missing_files:
        parser.error(f"dataset file(s) not found: {missing_files}")
    data = pd.concat((load_cic_csv(path) for path in args.dataset), ignore_index=True)
    counts = {str(label): int(count) for label, count in data.label.value_counts().to_dict().items()}
    if len(counts) < 2 or min(counts.values()) < 2:
        raise ValueError(f"Need at least two samples per class; class counts: {counts}")
    x_train, x_test, y_train, y_test = train_test_split(
        data[FEATURES], data.label, test_size=0.25, random_state=args.seed,
        stratify=data.label)
    model = RandomForestClassifier(n_estimators=args.trees, max_features="sqrt",
                                   class_weight="balanced_subsample",
                                   random_state=args.seed, n_jobs=-1,
                                   min_samples_leaf=2)
    model.fit(x_train, y_train)
    pred = model.predict(x_test)
    labels = ["benign", "attack"]
    attack_scores = model.predict_proba(x_test)[:, list(model.classes_).index("attack")]
    binary_test = (y_test.to_numpy() == "attack").astype(int)
    fpr, tpr, _ = roc_curve(binary_test, attack_scores)
    pr_precision, pr_recall, _ = precision_recall_curve(binary_test, attack_scores)
    roc_auc = float(roc_auc_score(binary_test, attack_scores))
    average_precision = float(average_precision_score(binary_test, attack_scores))
    threshold_sweep = []
    y_test_values = y_test.to_numpy()
    for low in (0.2, 0.3, 0.4):
        for high in (0.6, 0.7, 0.8):
            if high <= low:
                continue
            actioned = attack_scores >= low
            blocked = attack_scores > high
            throttled = actioned & ~blocked
            benign_mask = y_test_values == "benign"
            attack_mask = y_test_values == "attack"
            threshold_sweep.append({
                "low_threshold": low, "high_threshold": high,
                "benign_action_rate": float(actioned[benign_mask].mean()),
                "benign_throttle_rate": float(throttled[benign_mask].mean()),
                "benign_block_rate": float(blocked[benign_mask].mean()),
                "attack_action_rate": float(actioned[attack_mask].mean()),
                "attack_throttle_rate": float(throttled[attack_mask].mean()),
                "attack_block_rate": float(blocked[attack_mask].mean())})
    cv_result = None
    if args.cv_folds:
        if args.cv_folds < 2:
            parser.error("--cv-folds must be 0 or at least 2")
        smallest_training_class = int(y_train.value_counts().min())
        if smallest_training_class < args.cv_folds:
            parser.error(f"each training class needs at least {args.cv_folds} rows for CV; "
                         f"smallest class has {smallest_training_class}")
        cv_frame = pd.concat([x_train, y_train.rename("label")], axis=1)
        if len(cv_frame) > args.cv_max_rows:
            cv_frame = (cv_frame.groupby("label", group_keys=False)
                        .sample(frac=args.cv_max_rows / len(cv_frame),
                                random_state=args.seed))
        cv_model = RandomForestClassifier(n_estimators=min(args.trees, 100),
                                          max_features="sqrt",
                                          class_weight="balanced_subsample",
                                          random_state=args.seed, n_jobs=-1,
                                          min_samples_leaf=2)
        splitter = StratifiedKFold(n_splits=args.cv_folds, shuffle=True,
                                   random_state=args.seed)
        scores = cross_val_score(cv_model, cv_frame[FEATURES], cv_frame.label,
                                 cv=splitter, scoring="f1_macro", n_jobs=1)
        cv_result = {"folds": args.cv_folds,
                     "rows": int(len(cv_frame)),
                     "macro_f1_by_fold": [float(x) for x in scores],
                     "macro_f1_mean": float(scores.mean()),
                     "macro_f1_std": float(scores.std())}
    report = {"source_files": [path.name for path in args.dataset],
              "data_scope": "combined CICFlowMeter CSV files",
              "source_rows": int(len(data)), "class_counts": counts,
              "features": FEATURES, "label_mapping": "BENIGN/NORMAL -> benign; all other labels -> attack",
              "split": {"train_fraction": 0.75, "test_fraction": 0.25,
                        "stratified": True, "seed": args.seed},
              "test_samples": int(len(y_test)),
              "cross_validation_on_training_split": cv_result,
              "threshold_sweep": threshold_sweep,
              "accuracy": float(accuracy_score(y_test, pred)),
              "macro_f1": float(f1_score(y_test, pred, average="macro")),
              "weighted_f1": float(f1_score(y_test, pred, average="weighted")),
              "weighted_precision": float(precision_score(y_test, pred, average="weighted", zero_division=0)),
              "weighted_recall": float(recall_score(y_test, pred, average="weighted", zero_division=0)),
              "roc_auc": roc_auc,
              "average_precision": average_precision,
              "feature_importances": {feature: float(value) for feature, value
                                      in zip(FEATURES, model.feature_importances_)},
              "confusion_matrix_labels": labels,
              "confusion_matrix": confusion_matrix(y_test, pred, labels=labels).tolist(),
              "classification_report": classification_report(y_test, pred, output_dict=True, zero_division=0),
              "limitations": ["random row split may leak related flows across partitions",
                              "CIC whole-flow rows are approximated as two-second sampling windows",
                              "single 5-feature representation; verify feature distributions before deployment",
                              "results apply to this file and split only"]}
    args.output.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output / "model.joblib")
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    axes[0].plot(fpr, tpr, label=f"ROC AUC = {roc_auc:.3f}")
    axes[0].plot([0, 1], [0, 1], linestyle="--", color="#888888")
    axes[0].set(title="ROC curve", xlabel="False positive rate", ylabel="True positive rate")
    axes[0].legend(loc="lower right")
    axes[1].plot(pr_recall, pr_precision,
                 label=f"Average precision = {average_precision:.3f}")
    axes[1].set(title="Precision-recall curve", xlabel="Recall", ylabel="Precision")
    axes[1].legend(loc="lower left")
    for ax in axes:
        ax.grid(True, alpha=.25)
    fig.tight_layout()
    fig.savefig(args.output / "evaluation_curves.png", dpi=160)
    plt.close(fig)
    (args.output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("source_rows", "class_counts", "test_samples",
                                             "accuracy", "macro_f1", "weighted_f1")}, indent=2))


if __name__ == "__main__":
    main()
