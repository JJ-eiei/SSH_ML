"""
train_type_model.py -- stage-2 model: WHICH kind of brute-force attack.

Two-stage design:
  stage 1 (unchanged): ssh_bruteforce_model_v3.joblib  -> Attack / Legit
  stage 2 (this file): ssh_attack_type_model_v3.joblib -> attack type,
                       only meaningful for sessions stage 1 flags as Attack.

Training data: the SAME train/test split as the stage-1 model
(test_size=0.25, random_state=42, stratified by Attack_Type over the whole
dataset), then keep only attack sessions. `ambiguous_attack` is excluded:
it is not an attack technique but a deliberately legit-looking case that
stage 1 cannot flag anyway, so it has no meaningful "type" to show.

Same 16 features, same RF settings as stage 1 (400 trees, depth 8,
class_weight="balanced", random_state=42).

Outputs (paths relative to the repo root):
  v3/ssh_attack_type_model_v3.joblib       model bundle
  backend/ssh_attack_type_model_v3.joblib  copy for the FastAPI backend
  web/model/forest_type.json               exported trees for the browser
  v3/type_model_eval.json                  metrics (test, OOD, sanity checks)

Run from anywhere:  python v3/train_type_model.py
"""

import json
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
V3 = ROOT / "v3"

FEATURE_COLUMNS = [
    "fail_ratio", "n_failed", "n_success", "invalid_ratio", "publickey_ratio",
    "n_unique_usernames", "targets_default_username", "ends_after_success",
    "duration_seconds", "std_inter_arrival_s", "attempts_per_minute",
    "ip_session_count", "ip_active_span_days", "ip_sessions_per_day", "ip_total_events",
    "distinct_ips_same_target_15min",
]

EXCLUDED_TYPES = ["ambiguous_attack"]

# Display names + MITRE ATT&CK mapping (Brute Force, T1110).
TYPE_INFO = {
    "burst_bruteforce":             {"th": "Burst brute force — ยิงรัวใส่บัญชีเดียว", "mitre": "T1110.001"},
    "focused_bruteforce":           {"th": "Focused brute force — เดารหัสเจาะจงบัญชี", "mitre": "T1110.001"},
    "large_dictionary_scanner":     {"th": "Dictionary scanner — ไล่ชื่อผู้ใช้จำนวนมาก", "mitre": "T1110.001"},
    "low_and_slow":                 {"th": "Low-and-slow — ยิงช้าเพื่อหลบการตรวจจับ", "mitre": "T1110.001"},
    "persistent_multiday_attacker": {"th": "Persistent multi-day — IP เดิมกลับมาหลายวัน", "mitre": "T1110.001"},
    "coordinated_botnet_spike":     {"th": "Botnet — หลาย IP ยิงเป้าเดียวพร้อมกัน", "mitre": "T1110"},
    "password_spray":               {"th": "Password spraying — รหัสยอดฮิตกับหลายบัญชี", "mitre": "T1110.003"},
    "credential_stuffing":          {"th": "Credential stuffing — ใช้รหัสที่หลุดมา", "mitre": "T1110.004"},
}

LOW_CONFIDENCE = 0.6  # below this the UI shows "not sure (closest: ...)"
RF_PARAMS = dict(n_estimators=400, max_depth=8, class_weight="balanced", random_state=42, n_jobs=-1)


def load_splits():
    df = pd.read_csv(V3 / "ssh_features_v3.csv")
    ood = pd.read_csv(V3 / "ssh_features_v3_ood.csv")
    # identical split to the stage-1 model (retrain_rf.py / notebook)
    train_df, test_df = train_test_split(df, test_size=0.25, random_state=42, stratify=df["Attack_Type"])
    keep = lambda d: d[(d["Label"] == 1) & (~d["Attack_Type"].isin(EXCLUDED_TYPES))]
    return keep(train_df), keep(test_df), keep(ood), train_df, test_df, ood


def evaluate(model, X, y):
    pred = model.predict(X)
    proba = model.predict_proba(X).max(axis=1)
    labels = list(model.classes_)
    return {
        "n": int(len(y)),
        "accuracy": float(accuracy_score(y, pred)),
        "macro_f1": float(f1_score(y, pred, average="macro")),
        "per_class": classification_report(y, pred, labels=labels, output_dict=True, zero_division=0),
        "confusion_matrix": {"labels": labels,
                             "matrix": confusion_matrix(y, pred, labels=labels).tolist()},
        "low_confidence_fraction": float((proba < LOW_CONFIDENCE).mean()),
    }


def export_forest(model, out_path):
    trees = []
    for est in model.estimators_:
        t = est.tree_
        nodes = []
        for i in range(t.node_count):
            if t.children_left[i] == -1:
                v = t.value[i][0]
                v = v / v.sum()
                nodes.append({"leaf": True, "p": [round(float(a), 6) for a in v]})
            else:
                nodes.append({"leaf": False, "f": int(t.feature[i]), "t": float(t.threshold[i]),
                              "l": int(t.children_left[i]), "r": int(t.children_right[i])})
        trees.append(nodes)
    out = {
        "model_type": "random_forest_multiclass",
        "model_version": "v3-type",
        "n_estimators": model.n_estimators,
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(model.classes_),
        "low_confidence": LOW_CONFIDENCE,
        "trees": trees,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, separators=(",", ":")))
    return out


def forest_predict(forest, x):
    acc = np.zeros(len(forest["classes"]))
    for nodes in forest["trees"]:
        i = 0
        while not nodes[i]["leaf"]:
            n = nodes[i]
            i = n["l"] if x[n["f"]] <= n["t"] else n["r"]
        acc += nodes[i]["p"]
    return acc / len(forest["trees"])


def main():
    trA, teA, oodA, train_df, test_df, ood = load_splits()
    model = RandomForestClassifier(**RF_PARAMS).fit(trA[FEATURE_COLUMNS], trA["Attack_Type"])
    assert set(model.classes_) == set(TYPE_INFO), model.classes_

    report = {
        "rf_params": {k: v for k, v in RF_PARAMS.items() if k != "n_jobs"},
        "excluded_types": EXCLUDED_TYPES,
        "train_counts": trA["Attack_Type"].value_counts().to_dict(),
        "train": evaluate(model, trA[FEATURE_COLUMNS], trA["Attack_Type"]),
        "test": evaluate(model, teA[FEATURE_COLUMNS], teA["Attack_Type"]),
        "ood": evaluate(model, oodA[FEATURE_COLUMNS], oodA["Attack_Type"]),
    }

    # sanity check: same pipeline with shuffled labels should collapse to chance
    rng = np.random.default_rng(0)
    shuffled = RandomForestClassifier(**RF_PARAMS).fit(
        trA[FEATURE_COLUMNS], rng.permutation(trA["Attack_Type"].values))
    report["shuffled_label_test_macro_f1"] = float(
        f1_score(teA["Attack_Type"], shuffled.predict(teA[FEATURE_COLUMNS]), average="macro"))
    report["n_classes"] = len(TYPE_INFO)

    # what the excluded ambiguous_attack sessions would be labelled (for transparency)
    amb = ood[ood["Attack_Type"].isin(EXCLUDED_TYPES)]
    if len(amb):
        p = model.predict_proba(amb[FEATURE_COLUMNS])
        report["ambiguous_attack_ood"] = {
            "n": int(len(amb)),
            "predicted_as": pd.Series(model.classes_[p.argmax(1)]).value_counts().to_dict(),
            "low_confidence_fraction": float((p.max(1) < LOW_CONFIDENCE).mean()),
        }

    bundle = {"model": model, "feature_columns": FEATURE_COLUMNS, "classes": list(model.classes_),
              "type_info": TYPE_INFO, "excluded_types": EXCLUDED_TYPES, "low_confidence": LOW_CONFIDENCE,
              "model_name": "random_forest_attack_type"}
    joblib.dump(bundle, V3 / "ssh_attack_type_model_v3.joblib")
    shutil.copy(V3 / "ssh_attack_type_model_v3.joblib", ROOT / "backend" / "ssh_attack_type_model_v3.joblib")

    forest = export_forest(model, ROOT / "web" / "model" / "forest_type.json")
    X = oodA[FEATURE_COLUMNS].sample(60, random_state=0)
    diff = np.abs(model.predict_proba(X) - np.array([forest_predict(forest, x) for x in X.values])).max()
    report["export_max_abs_diff_vs_sklearn"] = float(diff)
    report["forest_type_json_kb"] = round((ROOT / "web" / "model" / "forest_type.json").stat().st_size / 1024, 1)

    (V3 / "type_model_eval.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))

    for split in ("train", "test", "ood"):
        r = report[split]
        print(f"{split:5s} n={r['n']:5d} acc={r['accuracy']:.4f} macroF1={r['macro_f1']:.4f} "
              f"low-conf={r['low_confidence_fraction']:.3f}")
    print("shuffled-label test macroF1:", round(report["shuffled_label_test_macro_f1"], 3),
          f"({report['n_classes']} classes -> real signal is gone)")
    print("export max |diff| vs sklearn:", diff, " forest_type.json:", report["forest_type_json_kb"], "KB")
    if "ambiguous_attack_ood" in report:
        print("ambiguous_attack (excluded) would be labelled:", report["ambiguous_attack_ood"])


if __name__ == "__main__":
    main()
