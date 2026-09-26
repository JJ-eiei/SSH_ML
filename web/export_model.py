import json
import joblib
import numpy as np

obj = joblib.load("ssh_bruteforce_model_v2.joblib")
model = obj["model"]
feature_columns = obj["feature_columns"]

def export_tree(tree):
    t = tree.tree_
    nodes = []
    for i in range(t.node_count):
        if t.children_left[i] == -1:  # leaf
            # value shape: (n_nodes, n_outputs, n_classes) -> proba of class 1
            v = t.value[i][0]
            proba = float(v[1] / v.sum())
            nodes.append({"leaf": True, "p": round(proba, 6)})
        else:
            nodes.append({
                "leaf": False,
                "f": int(t.feature[i]),
                "t": float(t.threshold[i]),
                "l": int(t.children_left[i]),
                "r": int(t.children_right[i]),
            })
    return nodes

forest_json = {
    "model_type": "random_forest",
    "n_estimators": model.n_estimators,
    "feature_columns": feature_columns,
    "trees": [export_tree(est) for est in model.estimators_],
}

with open("web/model/forest.json", "w") as f:
    json.dump(forest_json, f)

print("Exported", len(forest_json["trees"]), "trees")
import os
print("File size:", os.path.getsize("web/model/forest.json") / 1024, "KB")

# quick sanity check: re-implement prediction in pure python and compare to sklearn
import pandas as pd
df = pd.read_csv("ssh_dataset_ground_truth_v2.csv", parse_dates=["Timestamp"])

DEFAULT_USERNAMES = {"root","admin","test","guest","pi","oracle","ubuntu","mysql","postgres","ftpuser"}

def shannon_entropy(counts):
    probs = counts / counts.sum()
    return float(-(probs * np.log2(probs)).sum())

def extract_session_features(g):
    g = g.sort_values("Timestamp")
    n_events = len(g)
    n_failed = (g["Event"] == "Failed password").sum()
    n_success = (g["Event"] == "Accepted password").sum()
    user_counts = g["Username"].value_counts()
    duration = (g["Timestamp"].max() - g["Timestamp"].min()).total_seconds()
    if n_events > 1:
        ia = g["Timestamp"].diff().dt.total_seconds().dropna()
        mean_ia, median_ia, std_ia, min_ia = ia.mean(), ia.median(), ia.std(ddof=0), ia.min()
    else:
        mean_ia = median_ia = std_ia = min_ia = 0.0
    attempts_per_min = n_events / ((duration / 60) + 1e-6)
    return pd.Series({
        "n_events": n_events, "n_failed": n_failed, "n_success": n_success,
        "fail_ratio": n_failed / n_events,
        "n_unique_usernames": g["Username"].nunique(),
        "username_entropy": shannon_entropy(user_counts.values),
        "targets_default_username": int(bool(set(g["Username"]) & DEFAULT_USERNAMES)),
        "n_unique_ports": g["Source_Port"].nunique(),
        "duration_seconds": duration,
        "mean_inter_arrival_s": mean_ia, "median_inter_arrival_s": median_ia,
        "std_inter_arrival_s": std_ia, "min_inter_arrival_s": min_ia,
        "attempts_per_minute": attempts_per_min,
    })

sample_sessions = df["Session_ID"].drop_duplicates().sample(30, random_state=0)
feats = df[df["Session_ID"].isin(sample_sessions)].groupby("Session_ID").apply(extract_session_features)
X = feats[feature_columns].values
sk_proba = model.predict_proba(X)[:, 1]

def predict_tree(nodes, x):
    i = 0
    while not nodes[i]["leaf"]:
        node = nodes[i]
        i = node["l"] if x[node["f"]] <= node["t"] else node["r"]
    return nodes[i]["p"]

def predict_forest(trees, x):
    return sum(predict_tree(t, x) for t in trees) / len(trees)

py_proba = np.array([predict_forest(forest_json["trees"], x) for x in X])
max_diff = np.max(np.abs(sk_proba - py_proba))
print("Max diff sklearn vs re-implemented forest:", max_diff)
