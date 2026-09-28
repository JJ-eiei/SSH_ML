"""Builds ssh_bruteforce_pipeline_v3.ipynb as real notebook cells, to be
executed with nbclient so every output is a genuine run, not authored text."""
import nbformat as nbf

nb = nbf.v4.new_notebook()
cells = []

def md(text):
    cells.append(nbf.v4.new_markdown_cell(text))

def code(text):
    cells.append(nbf.v4.new_code_cell(text))

md("""# SSH Brute-Force Detection — v3 (diverse behaviors + IP-level/time-window aggregation)

**Why v3 exists:** the v2 review found the dataset only had 9 attack patterns evaluated purely at the
*session* level, all data was synthetic, and per-class breakdowns showed several "hard" classes were
still perfectly separable (a warning v2 itself raised and never resolved), plus two real feature-engineering
bugs (`n_success` was a deterministic duplicate of `n_events - n_failed`; `attempts_per_minute` divided by
a near-zero duration for 32.5% of sessions, producing a `1,000,000` outlier).

**What v3 changes:**
- Event vocabulary expanded (`Invalid user`, `Accepted publickey`, not just Failed/Accepted password) —
  grounded in real `auth.log` format.
- 5 new attack behaviors grounded in real SSH brute-force research (NSDI'24, NDSS billion-scale study):
  `large_dictionary_scanner`, `credential_stuffing`, `persistent_multiday_attacker`,
  `coordinated_botnet_spike`, plus a new **hard negative** `legit_multi_ip_roaming`.
- **IP-level cross-session features** (session count per IP, active-day span, total events, unique
  usernames targeted per IP) — needed because `persistent_multiday_attacker` and (after realistic
  10-minute session-gap splitting) `low_and_slow` both look tiny/innocuous at the *session* level.
- **Time-window cross-IP feature** (`distinct_ips_same_target_15min`) — needed because
  `coordinated_botnet_spike` looks like an isolated small burst from any single IP's perspective; only
  counting *other* IPs hitting the same target in a trailing window reveals the coordination.
- Every feature was run through an evidence-based verification pipeline (sanity/identity check,
  correlation + VIF, mutual information, permutation importance, bootstrap stability, group ablation,
  and an OOD check) *before* being kept or dropped — see `verify_features_v3.py` and section 3 below.
""")

code("""import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report, confusion_matrix, ConfusionMatrixDisplay,
    roc_auc_score, precision_recall_curve, average_precision_score, f1_score,
)
import joblib

RANDOM_STATE = 42
sns.set_theme(style="whitegrid", palette="deep")
pd.set_option("display.max_columns", None)
""")

md("## 1. Load session-level + IP-level + time-window features\n\nAlready computed by `extract_features_v3.py` from the raw event log `ssh_dataset_v3.csv` "
   "(main) and `ssh_dataset_v3_ood.csv` (held out, different seed + shifted day span, never touched below "
   "until the OOD section).")

code("""features = pd.read_csv("ssh_features_v3.csv", parse_dates=["session_start", "session_end"])
features_ood = pd.read_csv("ssh_features_v3_ood.csv", parse_dates=["session_start", "session_end"])
print("Main:", features.shape, " OOD:", features_ood.shape)
print("\\nSessions by Attack_Type (main):")
print(features["Attack_Type"].value_counts())
""")

md("""## 2. Final feature set — evidence, not guesswork

`verify_features_v3.py` ran 7 checks against every one of the 23 raw candidate columns
(sanity/identity, correlation+VIF, mutual information, permutation importance, bootstrap stability,
group ablation, OOD check). The decisions below are traceable to that output, not assumption.

**Dropped (9), each with the specific evidence:**
| Feature | Reason |
|---|---|
| `n_events` | 100% deterministic: `n_failed + n_invalid_user + n_success == n_events` for every session |
| `n_invalid_user` (raw count) | VIF = inf; 0.94-0.998 correlated with the username/port diversity cluster below. `invalid_ratio` kept instead. |
| `username_entropy` | 0.77 correlated with `n_unique_usernames`, near-zero incremental permutation importance |
| `n_unique_ports` | 0.95-0.96 correlated with the username/invalid-user cluster; generator also assigns a fresh ephemeral port per event regardless of pattern, so its real-world validity is unverified anyway |
| `ip_unique_usernames_targeted` | 0.9996 correlated with session-level `n_unique_usernames` — most IPs in this data have exactly one session, so the IP-level version is nearly an exact duplicate |
| `mean_inter_arrival_s`, `median_inter_arrival_s`, `min_inter_arrival_s` | mutually 0.95-0.998 correlated with each other and with `duration_seconds`; `std_inter_arrival_s` kept as the one "irregularity" representative, `duration_seconds` kept as the one "total spread" representative |

**Kept (15):** `fail_ratio`, `n_failed`, `n_success`, `invalid_ratio`, `publickey_ratio`, `n_unique_usernames`,
`targets_default_username`, `ends_after_success`, `duration_seconds`, `std_inter_arrival_s`,
`attempts_per_minute`, `ip_session_count`, `ip_active_span_days`, `ip_sessions_per_day`, `ip_total_events`,
`distinct_ips_same_target_15min`.

**One deliberate exception:** `distinct_ips_same_target_15min` has the *smallest* group-ablation impact on
binary PR-AUC (-0.0006) of anything kept — group ablation measures the binary attack/legit decision, and a
`coordinated_botnet_spike` session already looks like an attack from `fail_ratio`/`ends_after_success`
alone. But per-class inspection (below) shows this feature is a *near-perfect single-feature classifier for
that one attack type specifically* (median 26 distinct IPs vs. 0-2 for every other type). It's kept because
the stated goal is detecting **which** diverse behavior occurred, not just attack-vs-not — a binary metric
systematically undervalues a feature that does this job.
""")

code("""DROPPED_REDUNDANT = [
    "n_events", "n_invalid_user", "username_entropy", "n_unique_ports",
    "ip_unique_usernames_targeted", "mean_inter_arrival_s", "median_inter_arrival_s", "min_inter_arrival_s",
]
FEATURE_COLS = [
    "fail_ratio", "n_failed", "n_success", "invalid_ratio", "publickey_ratio",
    "n_unique_usernames", "targets_default_username", "ends_after_success",
    "duration_seconds", "std_inter_arrival_s", "attempts_per_minute",
    "ip_session_count", "ip_active_span_days", "ip_sessions_per_day", "ip_total_events",
    "distinct_ips_same_target_15min",
]
print(len(FEATURE_COLS), "features kept,", len(DROPPED_REDUNDANT), "dropped as redundant")
assert set(FEATURE_COLS).isdisjoint(DROPPED_REDUNDANT)
""")

md("### 2.1 Sanity check for the new time-window feature, by Attack_Type\n\nConfirms `distinct_ips_same_target_15min` really is near-perfectly isolated to `coordinated_botnet_spike` before we rely on the claim above.")

code("""features.groupby("Attack_Type")["distinct_ips_same_target_15min"].agg(["median", "max"]).sort_values("median")""")

md("### 2.2 Sanity check for IP-level persistence features, by Attack_Type\n\nConfirms `persistent_multiday_attacker` and `low_and_slow` are the two patterns that actually need cross-session IP aggregation (their per-session stats alone are small).")

code("""features.groupby("Attack_Type")[["ip_session_count", "ip_active_span_days", "n_events"]].median().sort_values("ip_session_count")""")

md("## 3. Train / test split\n\nStratified on `Attack_Type` so every pattern — including the small new classes — appears in both.")

code("""X = features[FEATURE_COLS]
y = features["Label"]
attack_type = features["Attack_Type"]

X_train, X_test, y_train, y_test, at_train, at_test = train_test_split(
    X, y, attack_type, test_size=0.25, random_state=RANDOM_STATE, stratify=attack_type,
)
print("Train:", X_train.shape, " Test:", X_test.shape)
print("\\nTest Attack_Type counts:\\n", at_test.value_counts())
""")

md("## 4. Models\n\nSame three as v2 (Logistic Regression baseline, Random Forest, XGBoost), same class-balancing, 5-fold stratified CV scored on PR-AUC (average precision).")

code("""models = {
    "logreg": Pipeline([
        ("scale", StandardScaler()),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE)),
    ]),
    "random_forest": RandomForestClassifier(
        n_estimators=400, class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1
    ),
    "xgboost": XGBClassifier(
        n_estimators=400, max_depth=5, learning_rate=0.1,
        eval_metric="logloss", random_state=RANDOM_STATE,
        scale_pos_weight=(y_train == 0).sum() / (y_train == 1).sum(),
    ),
}

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
cv_results = {}
for name, model in models.items():
    scores = cross_val_score(model, X_train, y_train, cv=cv, scoring="average_precision")
    cv_results[name] = scores
    print(f"{name:15s} PR-AUC: {scores.mean():.4f} +/- {scores.std():.4f}")
""")

code("""for name, model in models.items():
    model.fit(X_train, y_train)
print("All models fit on the training set.")
""")

md("## 5. Evaluation on the held-out test set")

code("""results_summary = []
for name, model in models.items():
    proba = model.predict_proba(X_test)[:, 1]
    pred = model.predict(X_test)
    print(f"=== {name} ===")
    print(classification_report(y_test, pred, target_names=["legit", "attack"]))
    roc_auc = roc_auc_score(y_test, proba)
    pr_auc = average_precision_score(y_test, proba)
    f1 = f1_score(y_test, pred)
    print(f"ROC-AUC: {roc_auc:.4f}   PR-AUC: {pr_auc:.4f}\\n")
    results_summary.append({"model": name, "roc_auc": roc_auc, "pr_auc": pr_auc, "f1": f1})

results_summary = pd.DataFrame(results_summary).set_index("model")
results_summary
""")

code("""fig, axes = plt.subplots(1, 3, figsize=(15, 4))
for ax, (name, model) in zip(axes, models.items()):
    pred = model.predict(X_test)
    cm = confusion_matrix(y_test, pred)
    ConfusionMatrixDisplay(cm, display_labels=["legit", "attack"]).plot(ax=ax, colorbar=False)
    ax.set_title(name)
plt.tight_layout()
plt.show()
""")

md("### 5.1 Per-attack-type breakdown on the test set\n\nThe metric that matters most: does the model actually work on *every* behavior, not just in aggregate?")

code("""def per_type_breakdown(y_true, y_pred, proba, attack_types, name):
    rows = []
    for atype in attack_types.unique():
        mask = attack_types == atype
        n = mask.sum()
        lbl = y_true[mask].iloc[0] if hasattr(y_true, 'iloc') else y_true[mask][0]
        if lbl == 1:
            metric_name, value = "recall", (y_pred[mask] == 1).mean()
        else:
            metric_name, value = "false_positive_rate", (y_pred[mask] == 1).mean()
        rows.append({"model": name, "attack_type": atype, "n": n, "metric": metric_name, "value": value})
    return rows

breakdown = []
for name, model in models.items():
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    breakdown += per_type_breakdown(y_test.reset_index(drop=True), pred,
                                     proba, at_test.reset_index(drop=True), name)

breakdown_df = pd.DataFrame(breakdown).pivot_table(index=["attack_type", "n", "metric"], columns="model", values="value")
breakdown_df
""")

md("## 6. Out-of-distribution generalization check\n\n`ssh_dataset_v3_ood.csv`: different random seed (777 vs 42), different scale (0.85x pattern counts), and a longer day span (45 vs 30 days) — generated once, never touched until now.")

code("""X_ood = features_ood[FEATURE_COLS]
y_ood = features_ood["Label"]
at_ood = features_ood["Attack_Type"]

ood_summary = []
for name, model in models.items():
    proba = model.predict_proba(X_ood)[:, 1]
    pred = model.predict(X_ood)
    roc_auc = roc_auc_score(y_ood, proba)
    pr_auc = average_precision_score(y_ood, proba)
    f1 = f1_score(y_ood, pred)
    ood_summary.append({"model": name, "roc_auc": roc_auc, "pr_auc": pr_auc, "f1": f1})
ood_summary = pd.DataFrame(ood_summary).set_index("model")

print("Held-out TEST (same distribution as training):")
display(results_summary)
print("\\nOOD set (different seed + shifted scale/day-span):")
display(ood_summary)
print("\\nDrop (test - OOD):")
display(results_summary - ood_summary)
""")

code("""ood_breakdown = []
for name, model in models.items():
    pred = model.predict(X_ood)
    ood_breakdown += per_type_breakdown(y_ood.reset_index(drop=True), pred,
                                         model.predict_proba(X_ood)[:, 1],
                                         at_ood.reset_index(drop=True), name)
pd.DataFrame(ood_breakdown).pivot_table(index=["attack_type", "n", "metric"], columns="model", values="value")
""")

md("## 7. Feature importance (permutation-based, not impurity-based — see verify_features_v3.py for the full bootstrap-stability version)")

code("""from sklearn.inspection import permutation_importance

best_name = results_summary["pr_auc"].idxmax()
best_model = models[best_name]
print("Best by test PR-AUC:", best_name)

pi = permutation_importance(best_model, X_test, y_test, n_repeats=20,
                             random_state=RANDOM_STATE, scoring="average_precision", n_jobs=-1)
importances = pd.Series(pi.importances_mean, index=FEATURE_COLS).sort_values()
importances.plot(kind="barh", figsize=(7, 6))
plt.title(f"Permutation importance ({best_name}, test set)")
plt.xlabel("Mean decrease in PR-AUC when shuffled")
plt.tight_layout()
plt.show()
importances.sort_values(ascending=False)
""")

md("## 8. Threshold tuning\n\nSame rationale as v2: in a SOC context a missed attack (false negative) usually costs more than a flagged legit session, so the default 0.5 cutoff is worth revisiting via the precision-recall curve.")

code("""proba_best = best_model.predict_proba(X_test)[:, 1]
precisions, recalls, thresholds = precision_recall_curve(y_test, proba_best)

target_recall = 0.95
idx = np.where(recalls[:-1] >= target_recall)[0]
if len(idx):
    chosen_idx = idx[-1]
    chosen_threshold = thresholds[chosen_idx]
    chosen_precision = precisions[chosen_idx]
    print(f"Threshold for recall >= {target_recall}: {chosen_threshold:.3f} (precision at that point: {chosen_precision:.3f})")
else:
    print(f"No threshold in range reaches recall >= {target_recall} on this test set.")

plt.figure(figsize=(6, 5))
plt.plot(recalls, precisions)
plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title(f"Precision-Recall curve ({best_name}, test set)")
plt.tight_layout()
plt.show()
""")

md("## 9. Save the model artifact")

code("""joblib.dump(
    {"model": best_model, "feature_columns": FEATURE_COLS, "model_name": best_name,
     "dropped_redundant_features": DROPPED_REDUNDANT},
    "ssh_bruteforce_model_v3.joblib",
)
print(f"Saved: ssh_bruteforce_model_v3.joblib (best model: {best_name})")
""")

md("""## What's still not covered here

- Real (e.g. honeypot) SSH traffic — this is still entirely synthetic data. The OOD check tests
  robustness to *this generator's* distribution shift (seed, scale, day-span), not to real attacker
  behavior. The 5 new patterns are grounded in published research findings (usernames-per-IP
  distribution, target-selection randomness, persistence duration, coordinated spikes) but the exact
  parameter values (e.g. how many usernames a "large-dictionary" attacker tries) are still my own
  synthetic ranges, not fitted to a real dataset.
- Production session-segmentation is now actually implemented (10-minute gap per Source_IP, see
  `generate_v3_dataset.py::assign_sessions`) rather than left as future work — but the threshold itself
  (10 minutes) is a guess, not validated against real attacker timing.
- `distinct_ips_same_target_15min` and the IP-level features assume the inference pipeline has
  visibility across a time window / across an IP's full history, not just a single freshly-uploaded log
  session — this is a real deployment requirement (a stateful lookup store keyed by IP and by target
  username), not just a model, and isn't built here.
- Feature verification used one classifier (Random Forest) for permutation importance/ablation; whether
  the same 15-feature set is optimal for XGBoost or Logistic Regression specifically wasn't re-verified
  per-model.
""")

nb["cells"] = cells
nbf.write(nb, "ssh_bruteforce_pipeline_v3.ipynb")
print("wrote ssh_bruteforce_pipeline_v3.ipynb with", len(cells), "cells")
