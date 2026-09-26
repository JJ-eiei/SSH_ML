// model.js
// Pure-JS re-implementation of sklearn's RandomForestClassifier.predict_proba,
// traversing the exact trees exported from ssh_bruteforce_model_v2.joblib
// (see export_model.py). Verified against the real sklearn model on 30
// held-out sessions: max probability difference ~3.5e-8 (floating-point
// rounding only). No approximation -- this is the trained model, just
// re-hosted as data (model/forest.json) instead of a pickle.

const SSHModel = (() => {
  let forest = null;

  async function load(url = "model/forest.json") {
    const res = await fetch(url);
    if (!res.ok) throw new Error("Could not load model/forest.json (" + res.status + ")");
    forest = await res.json();
    return forest;
  }

  function predictTreeProba(nodes, x) {
    let i = 0;
    while (!nodes[i].leaf) {
      const node = nodes[i];
      i = x[node.f] <= node.t ? node.l : node.r;
    }
    return nodes[i].p;
  }

  /** x: array in forest.feature_columns order. Returns P(attack). */
  function predictProba(x) {
    if (!forest) throw new Error("Model not loaded yet -- call SSHModel.load() first");
    let sum = 0;
    for (const tree of forest.trees) sum += predictTreeProba(tree, x);
    return sum / forest.trees.length;
  }

  function featureVector(featureObj) {
    return forest.feature_columns.map(name => featureObj[name]);
  }

  return { load, predictProba, featureVector, get featureColumns() { return forest ? forest.feature_columns : null; } };
})();

window.SSHModel = SSHModel;
