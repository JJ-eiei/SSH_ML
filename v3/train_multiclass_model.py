"""
train_multiclass_model.py -- ONE Random Forest that says both
"attack or legit" and "which kind", replacing the earlier two-model setup.

Classes (11). Patterns that the 16 features cannot tell apart BY DESIGN of
the data generator are merged (see generate_v3_dataset.py docstrings):
  legit_login      = legit_success + legit_multi_ip_roaming
                     (roaming = one successful login per IP: identical to
                     legit_success at session/IP level; telling them apart
                     needs a per-USER cross-IP view we don't have)
  legit_typo       = legit_typo + ambiguous_legit
                     (ambiguous_legit = a typo user with more fails)
  shared_ip_legit
  + 8 attack types (MITRE ATT&CK T1110 family)
`ambiguous_attack` (an attack generated to look exactly like legit_typo) is
left out of TRAINING: it has no learnable signature. It is still in the
test/OOD sets and counted as an attack in the binary metrics below.

Decision rule (identical in backend/pipeline.py and web/js/model.js):
  risk  = sum of P(attack classes)
  risk >= threshold -> Attack, label = most likely ATTACK class
  else              -> Legit,  label = most likely LEGIT class
  label confidence  = P(label) / P(its group); < LOW_CONFIDENCE -> "not sure"
The threshold is chosen by 5-fold cross-validation on the TRAINING set only
(max F1), never on test data.

Same split as every earlier model: test_size=0.25, random_state=42,
stratified by the original Attack_Type over the whole dataset.

Outputs (repo-relative):
  v3/ssh_bruteforce_multiclass.joblib          model bundle
  backend/ssh_bruteforce_multiclass.joblib     copy for the FastAPI backend
  web/model/forest.json                        exported trees for the browser
  v3/multiclass_model_eval.json                metrics

Run: python v3/train_multiclass_model.py
"""

import json
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, average_precision_score, classification_report,
                             confusion_matrix, f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split

ROOT = Path(__file__).resolve().parent.parent
V3 = ROOT / "v3"

FEATURE_COLUMNS = [
    "fail_ratio", "n_failed", "n_success", "invalid_ratio", "publickey_ratio",
    "n_unique_usernames", "targets_default_username", "ends_after_success",
    "duration_seconds", "std_inter_arrival_s", "attempts_per_minute",
    "ip_session_count", "ip_active_span_days", "ip_sessions_per_day", "ip_total_events",
    "distinct_ips_same_target_15min",
]

CLASS_MAP = {  # original generator pattern -> model class
    "legit_success": "legit_login",
    "legit_multi_ip_roaming": "legit_login",
    "legit_typo": "legit_typo",
    "ambiguous_legit": "legit_typo",
    "shared_ip_legit": "shared_ip_legit",
    "burst_bruteforce": "burst_bruteforce",
    "focused_bruteforce": "focused_bruteforce",
    "large_dictionary_scanner": "large_dictionary_scanner",
    "low_and_slow": "low_and_slow",
    "persistent_multiday_attacker": "persistent_multiday_attacker",
    "coordinated_botnet_spike": "coordinated_botnet_spike",
    "password_spray": "password_spray",
    "credential_stuffing": "credential_stuffing",
}
NOT_TRAINED = ["ambiguous_attack"]
LEGIT_CLASSES = ["legit_login", "legit_typo", "shared_ip_legit"]
ATTACK_CLASSES = ["burst_bruteforce", "focused_bruteforce", "large_dictionary_scanner", "low_and_slow",
                  "persistent_multiday_attacker", "coordinated_botnet_spike", "password_spray",
                  "credential_stuffing"]
MITRE = {"burst_bruteforce": "T1110.001", "focused_bruteforce": "T1110.001",
         "large_dictionary_scanner": "T1110.001", "low_and_slow": "T1110.001",
         "persistent_multiday_attacker": "T1110.001", "coordinated_botnet_spike": "T1110",
         "password_spray": "T1110.003", "credential_stuffing": "T1110.004"}

LOW_CONFIDENCE = 0.6
# Hyper-parameters chosen by 5-fold CV on the TRAINING set only (mean of 3
# CV seeds; candidates max_features in {sqrt, 0.35, 0.5, 0.7}, max_depth in
# {8, 12}) -- see notebook section 4. Depth stays 8 to keep forest.json small.
# class_weight=None on purpose: "balanced" (used by the old binary model)
# inflates the many small attack classes and blurs the three legit classes.
RF_PARAMS = dict(n_estimators=400, max_depth=8, max_features=0.7, class_weight=None,
                 random_state=42, n_jobs=-1)


# ------------------------------------------------------------------ data --
def load_splits():
    df = pd.read_csv(V3 / "ssh_features_v3.csv")
    ood = pd.read_csv(V3 / "ssh_features_v3_ood.csv")
    train_df, test_df = train_test_split(df, test_size=0.25, random_state=42, stratify=df["Attack_Type"])
    for d in (train_df, test_df, ood):
        d["Class"] = d["Attack_Type"].map(CLASS_MAP)  # NaN for ambiguous_attack
    trainable = train_df[~train_df["Attack_Type"].isin(NOT_TRAINED)]
    return trainable, test_df, ood


# --------------------------------------------------------- decision rule --
def decide(proba, classes, threshold):
    """proba: (n, k) class probabilities in `classes` order.
    Returns risk, is_attack, label, label_confidence (arrays)."""
    classes = list(classes)
    a_idx = [classes.index(c) for c in ATTACK_CLASSES]
    l_idx = [classes.index(c) for c in LEGIT_CLASSES]
    # rounded so float noise can't flip the decision at threshold 1.00
    risk = np.round(proba[:, a_idx].sum(axis=1), 9)
    legit_mass = proba[:, l_idx].sum(axis=1)
    is_attack = risk >= threshold
    top_a = np.array(a_idx)[proba[:, a_idx].argmax(axis=1)]
    top_l = np.array(l_idx)[proba[:, l_idx].argmax(axis=1)]
    label_idx = np.where(is_attack, top_a, top_l)
    group_mass = np.where(is_attack, risk, legit_mass)
    conf = proba[np.arange(len(proba)), label_idx] / np.maximum(group_mass, 1e-12)
    return risk, is_attack, np.array(classes)[label_idx], conf


def pick_threshold(train_df):
    oof = cross_val_predict(RandomForestClassifier(**RF_PARAMS), train_df[FEATURE_COLUMNS], train_df["Class"],
                            cv=StratifiedKFold(5, shuffle=True, random_state=42), method="predict_proba")
    classes = sorted(train_df["Class"].unique())
    risk = oof[:, [classes.index(c) for c in ATTACK_CLASSES]].sum(axis=1)
    p, r, t = precision_recall_curve(train_df["Label"], risk)
    f1 = 2 * p * r / np.maximum(p + r, 1e-12)
    return round(float(t[f1[:-1].argmax()]), 2)


def evaluate(model, df, threshold):
    proba = model.predict_proba(df[FEATURE_COLUMNS])
    risk, is_attack, label, conf = decide(proba, model.classes_, threshold)
    y = df["Label"].values
    out = {
        "n_sessions": int(len(df)),
        "binary": {
            "pr_auc": float(average_precision_score(y, risk)),
            "roc_auc": float(roc_auc_score(y, risk)),
            "precision": float(precision_score(y, is_attack)),
            "recall": float(recall_score(y, is_attack)),
            "f1": float(f1_score(y, is_attack)),
            "accuracy": float(accuracy_score(y, is_attack)),
            "confusion_tn_fp_fn_tp": confusion_matrix(y, is_attack).ravel().tolist(),
        },
    }
    known = df["Class"].notna().values  # everything except ambiguous_attack
    yc, pc = df["Class"].values[known], label[known]
    labels = LEGIT_CLASSES + ATTACK_CLASSES
    out["classes"] = {
        "n_sessions": int(known.sum()),
        "accuracy": float(accuracy_score(yc, pc)),
        "macro_f1": float(f1_score(yc, pc, labels=labels, average="macro")),
        "per_class": classification_report(yc, pc, labels=labels, output_dict=True, zero_division=0),
        "confusion_matrix": {"labels": labels, "matrix": confusion_matrix(yc, pc, labels=labels).tolist()},
        "low_confidence_fraction": float((conf[known] < LOW_CONFIDENCE).mean()),
    }
    amb = ~known
    if amb.any():
        out["ambiguous_attack_not_trained"] = {
            "n": int(amb.sum()),
            "detected_as_attack": float(is_attack[amb].mean()),
            "labelled_as": pd.Series(label[amb]).value_counts().to_dict(),
        }
    # per original pattern: share detected in the right group + share given the right class
    rows = {}
    for pat, g in df.groupby("Attack_Type"):
        m = (df["Attack_Type"] == pat).values
        right_group = is_attack[m] == (g["Label"].values == 1)
        rows[pat] = {"n": int(m.sum()), "group_correct": float(right_group.mean()),
                     "class_correct": float((label[m] == CLASS_MAP[pat]).mean()) if pat in CLASS_MAP else None}
    out["by_original_pattern"] = rows
    return out


# ---------------------------------------------------------------- export --
def export_forest(model, threshold, out_path):
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
    forest = {
        "model_type": "random_forest_multiclass",
        "model_version": "v4-multiclass",
        "n_estimators": model.n_estimators,
        "feature_columns": FEATURE_COLUMNS,
        "classes": list(model.classes_),
        "attack_classes": ATTACK_CLASSES,
        "legit_classes": LEGIT_CLASSES,
        "threshold": threshold,
        "low_confidence": LOW_CONFIDENCE,
        "session_gap_minutes": 10,
        "trees": trees,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(forest, separators=(",", ":")))
    return forest


def forest_predict(forest, x):
    acc = np.zeros(len(forest["classes"]))
    for nodes in forest["trees"]:
        i = 0
        while not nodes[i]["leaf"]:
            n = nodes[i]
            # sklearn compares the float32 value of each feature with the split
            i = n["l"] if np.float32(x[n["f"]]) <= n["t"] else n["r"]
        acc += nodes[i]["p"]
    return acc / len(forest["trees"])


def main():
    train_df, test_df, ood = load_splits()
    threshold = pick_threshold(train_df)
    model = RandomForestClassifier(**RF_PARAMS).fit(train_df[FEATURE_COLUMNS], train_df["Class"])
    assert sorted(model.classes_) == sorted(LEGIT_CLASSES + ATTACK_CLASSES), model.classes_

    report = {
        "rf_params": {k: v for k, v in RF_PARAMS.items() if k != "n_jobs"},
        "class_map": CLASS_MAP, "not_trained": NOT_TRAINED,
        "threshold_from_train_cv": threshold,
        "train_class_counts": train_df["Class"].value_counts().to_dict(),
        "train": evaluate(model, train_df, threshold),
        "test": evaluate(model, test_df, threshold),
        "ood": evaluate(model, ood, threshold),
    }
    rng = np.random.default_rng(0)
    shuffled = RandomForestClassifier(**RF_PARAMS).fit(train_df[FEATURE_COLUMNS],
                                                       rng.permutation(train_df["Class"].values))
    known = test_df["Class"].notna()
    report["shuffled_label_test_class_macro_f1"] = float(
        f1_score(test_df.loc[known, "Class"], shuffled.predict(test_df.loc[known, FEATURE_COLUMNS]), average="macro"))

    bundle = {"model": model, "feature_columns": FEATURE_COLUMNS, "classes": list(model.classes_),
              "attack_classes": ATTACK_CLASSES, "legit_classes": LEGIT_CLASSES, "mitre": MITRE,
              "threshold": threshold, "low_confidence": LOW_CONFIDENCE, "class_map": CLASS_MAP,
              "session_gap_minutes": 10, "model_name": "random_forest_multiclass_v4"}
    joblib.dump(bundle, V3 / "ssh_bruteforce_multiclass.joblib")
    shutil.copy(V3 / "ssh_bruteforce_multiclass.joblib", ROOT / "backend" / "ssh_bruteforce_multiclass.joblib")

    forest = export_forest(model, threshold, ROOT / "web" / "model" / "forest.json")
    X = ood[FEATURE_COLUMNS].sample(80, random_state=0)
    diff = np.abs(model.predict_proba(X) - np.array([forest_predict(forest, x) for x in X.values])).max()
    report["export_max_abs_diff_vs_sklearn"] = float(diff)
    report["forest_json_kb"] = round((ROOT / "web" / "model" / "forest.json").stat().st_size / 1024, 1)
    (V3 / "multiclass_model_eval.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))

    print("threshold (5-fold CV on train):", threshold)
    for s in ("train", "test", "ood"):
        b, c = report[s]["binary"], report[s]["classes"]
        print(f"{s:5s} binary P={b['precision']:.4f} R={b['recall']:.4f} F1={b['f1']:.4f} PR-AUC={b['pr_auc']:.4f}"
              f" | classes acc={c['accuracy']:.4f} macroF1={c['macro_f1']:.4f} low-conf={c['low_confidence_fraction']:.3f}")
    print("shuffled-label test class macro F1:", round(report["shuffled_label_test_class_macro_f1"], 3))
    print("export max |diff|:", diff, " forest.json KB:", report["forest_json_kb"])
    print("ambiguous_attack (not trained), OOD:", report["ood"].get("ambiguous_attack_not_trained"))


if __name__ == "__main__":
    main()
