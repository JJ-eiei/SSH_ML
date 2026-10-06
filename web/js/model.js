// model.js
// Pure-JS re-implementation of sklearn's RandomForestClassifier.predict_proba,
// traversing trees exported to JSON (no approximation -- the trained model,
// re-hosted as data instead of a pickle).
//
// Two forests are used (two-stage design):
//   SSHModel     -- stage 1, model/forest.json:      P(attack)  (leaf "p" = number)
//                   exported by web/export_model_v3.py; verified vs sklearn ~3.5e-8
//   SSHTypeModel -- stage 2, model/forest_type.json: which attack type, only
//                   meaningful for sessions stage 1 flags   (leaf "p" = array)
//                   exported by v3/train_type_model.py; verified vs sklearn ~5e-9

// retryOnError: stage 1 retries on the next call (it is required, a transient
// network error shouldn't break the page for good); the optional stage-2
// model remembers a failure, so the live console doesn't refetch a 560 KB
// file on every keystroke.
function createForestModel(defaultUrl, { retryOnError = true } = {}) {
  let forest = null;
  let loading = null;   // one shared in-flight request for concurrent callers

  async function load(url = defaultUrl) {
    if (forest) return forest;
    if (!loading) {
      loading = fetch(url).then(res => {
        if (!res.ok) throw new Error(`Could not load ${url} (${res.status})`);
        return res.json();
      }).then(json => { forest = json; return forest; })
        .catch(err => { if (retryOnError) loading = null; throw err; });
    }
    return loading;
  }

  function leafFor(nodes, x) {
    let i = 0;
    while (!nodes[i].leaf) {
      const node = nodes[i];
      i = x[node.f] <= node.t ? node.l : node.r;
    }
    return nodes[i].p;
  }

  /** x: array in forest.feature_columns order.
   *  Binary forest -> P(attack) (number). Multiclass forest -> array of P(class). */
  function predictProba(x) {
    if (!forest) throw new Error("Model not loaded yet -- call load() first");
    const first = leafFor(forest.trees[0], x);
    if (typeof first === "number") {
      let sum = 0;
      for (const tree of forest.trees) sum += leafFor(tree, x);
      return sum / forest.trees.length;
    }
    const acc = new Array(first.length).fill(0);
    for (const tree of forest.trees) {
      const p = leafFor(tree, x);
      for (let k = 0; k < p.length; k++) acc[k] += p[k];
    }
    return acc.map(v => v / forest.trees.length);
  }

  function featureVector(featureObj) {
    return forest.feature_columns.map(name => featureObj[name]);
  }

  return {
    load, predictProba, featureVector,
    get featureColumns() { return forest ? forest.feature_columns : null; },
    get forest() { return forest; },
  };
}

const SSHModel = createForestModel("model/forest.json");

const SSHTypeModel = (() => {
  const base = createForestModel("model/forest_type.json", { retryOnError: false });
  /** Returns {type, confidence, lowConfidence, ranked:[{type, p}, ...]} */
  function predictType(featureObj) {
    const probs = base.predictProba(base.featureVector(featureObj));
    const classes = base.forest.classes;
    const ranked = classes.map((type, k) => ({ type, p: probs[k] })).sort((a, b) => b.p - a.p);
    const low = base.forest.low_confidence ?? 0.6;
    return { type: ranked[0].type, confidence: ranked[0].p, lowConfidence: ranked[0].p < low, ranked };
  }
  return { ...base, load: base.load, predictType,
           get featureColumns() { return base.featureColumns; }, get forest() { return base.forest; } };
})();

window.SSHModel = SSHModel;
window.SSHTypeModel = SSHTypeModel;
