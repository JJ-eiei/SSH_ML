import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, f1_score, classification_report

RANDOM_STATE = 42

DROPPED_REDUNDANT = [
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

features = pd.read_csv("/home/claude/v3/ssh_features_v3.csv")
X = features[FEATURE_COLS]
y = features["Label"]
attack_type = features["Attack_Type"]

X_train, X_test, y_train, y_test, at_train, at_test = train_test_split(
    X, y, attack_type, test_size=0.25, random_state=RANDOM_STATE, stratify=attack_type,
)

model = RandomForestClassifier(
    n_estimators=400, class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
    max_depth=8,  # capped so the JS-exported forest.json stays a reasonable size
)
model.fit(X_train, y_train)

proba = model.predict_proba(X_test)[:, 1]
pred = model.predict(X_test)
print("Test PR-AUC:", average_precision_score(y_test, proba))
print("Test F1:", f1_score(y_test, pred))
print(classification_report(y_test, pred))

# OOD check
features_ood = pd.read_csv("/home/claude/v3/ssh_features_v3_ood.csv")
X_ood = features_ood[FEATURE_COLS]
y_ood = features_ood["Label"]
proba_ood = model.predict_proba(X_ood)[:, 1]
pred_ood = model.predict(X_ood)
print("\nOOD PR-AUC:", average_precision_score(y_ood, proba_ood))
print("OOD F1:", f1_score(y_ood, pred_ood))

joblib.dump(
    {"model": model, "feature_columns": FEATURE_COLS, "model_name": "random_forest",
     "dropped_redundant_features": DROPPED_REDUNDANT},
    "/home/claude/v3/deploy/ssh_bruteforce_model_v3.joblib",
)
print("\nSaved ssh_bruteforce_model_v3.joblib (RandomForest, max_depth=8)")

# tree size sanity check
depths = [est.get_depth() for est in model.estimators_]
n_nodes = [est.tree_.node_count for est in model.estimators_]
print("Tree depths: min", min(depths), "max", max(depths), "mean", sum(depths)/len(depths))
print("Total nodes across all trees:", sum(n_nodes))
