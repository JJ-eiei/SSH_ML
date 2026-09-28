import json
import os
import joblib
import numpy as np
import pandas as pd

obj = joblib.load("/home/claude/v3/deploy/ssh_bruteforce_model_v3.joblib")
model = obj["model"]
feature_columns = obj["feature_columns"]

def export_tree(tree):
    t = tree.tree_
    nodes = []
    for i in range(t.node_count):
        if t.children_left[i] == -1:  # leaf
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
    "model_version": "v3",
    "n_estimators": model.n_estimators,
    "feature_columns": feature_columns,
    "trees": [export_tree(est) for est in model.estimators_],
}

out_path = "/home/claude/v3/deploy/forest.json"
with open(out_path, "w") as f:
    json.dump(forest_json, f)

print("Exported", len(forest_json["trees"]), "trees")
print("File size:", os.path.getsize(out_path) / 1024, "KB")

# verify against sklearn on held-out sessions from the OOD set (never trained on)
features_ood = pd.read_csv("/home/claude/v3/ssh_features_v3_ood.csv")
sample = features_ood.sample(40, random_state=0)
X = sample[feature_columns].values
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
