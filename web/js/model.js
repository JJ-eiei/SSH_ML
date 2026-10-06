// model.js
// Pure-JS re-implementation of sklearn's RandomForestClassifier.predict_proba,
// traversing the trees exported to model/forest.json by
// v3/train_multiclass_model.py (no approximation -- the trained model,
// re-hosted as data instead of a pickle; verified vs sklearn ~2e-8).
//
// ONE multiclass model, 11 classes (3 legit behaviours + 8 attack types).
// Decision rule (identical to backend/pipeline.py decide() and the training
// script):
//   risk = sum of P(attack classes)
//   risk >= threshold -> Attack, label = most likely ATTACK class
//   else              -> Legit,  label = most likely LEGIT class
//   confidence = P(label) / P(label's group); below low_confidence -> "not sure"

/**
 * Apply the decision rule to a {class: probability} map.
 * meta = {attackClasses, legitClasses, lowConfidence}
 */
function decideClass(classProba, threshold, meta) {
  let risk = 0, legitMass = 0;
  let bestA = null, bestL = null;
  for (const c of meta.attackClasses) {
    const p = classProba[c] || 0;
    risk += p;
    if (bestA === null || p > classProba[bestA]) bestA = c;
  }
  for (const c of meta.legitClasses) {
    const p = classProba[c] || 0;
    legitMass += p;
    if (bestL === null || p > classProba[bestL]) bestL = c;
  }
  risk = Math.round(risk * 1e9) / 1e9;  // float noise must not flip the decision at threshold 1.00
  const isAttack = risk >= threshold;
  const label = isAttack ? bestA : bestL;
  const groupMass = isAttack ? risk : legitMass;
  const confidence = (classProba[label] || 0) / Math.max(groupMass, 1e-12);
  return { risk, isAttack, label, confidence, lowConfidence: confidence < (meta.lowConfidence ?? 0.6) };
}

const SSHModel = (() => {
  let forest = null;
  let loading = null;  // one shared in-flight request; retried after a failure

  async function load(url = "model/forest.json") {
    if (forest) return forest;
    if (!loading) {
      loading = fetch(url).then(res => {
        if (!res.ok) throw new Error(`Could not load ${url} (${res.status})`);
        return res.json();
      }).then(json => {
        if (!Array.isArray(json.classes)) throw new Error(`${url} is not a multiclass model`);
        forest = json;
        return forest;
      }).catch(err => { loading = null; throw err; });
    }
    return loading;
  }

  function leafFor(nodes, x) {
    let i = 0;
    while (!nodes[i].leaf) {
      const node = nodes[i];
      // sklearn compares the float32 value of the feature with the split
      // threshold; Math.fround reproduces that exactly
      i = Math.fround(x[node.f]) <= node.t ? node.l : node.r;
    }
    return nodes[i].p;
  }

  /** x: array in forest.feature_columns order -> {class: probability} */
  function predictClassProba(x) {
    if (!forest) throw new Error("Model not loaded yet -- call SSHModel.load() first");
    const k = forest.classes.length;
    const acc = new Array(k).fill(0);
    for (const tree of forest.trees) {
      const p = leafFor(tree, x);
      for (let j = 0; j < k; j++) acc[j] += p[j];
    }
    const out = {};
    forest.classes.forEach((c, j) => { out[c] = acc[j] / forest.trees.length; });
    return out;
  }

  function featureVector(featureObj) {
    return forest.feature_columns.map(name => featureObj[name]);
  }

  function meta() {
    return {
      attackClasses: forest.attack_classes,
      legitClasses: forest.legit_classes,
      lowConfidence: forest.low_confidence,
      threshold: forest.threshold,
    };
  }

  /** features object -> {classProba, risk, isAttack, label, confidence, lowConfidence} */
  function classify(featureObj, threshold = forest.threshold) {
    const classProba = predictClassProba(featureVector(featureObj));
    return { classProba, ...decideClass(classProba, threshold, meta()) };
  }

  return {
    load, predictClassProba, featureVector, classify, meta,
    get featureColumns() { return forest ? forest.feature_columns : null; },
    get threshold() { return forest ? forest.threshold : null; },
  };
})();

window.SSHModel = SSHModel;
window.decideClass = decideClass;
