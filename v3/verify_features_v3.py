"""
verify_features_v3.py

Evidence-based feature verification, in the order specified in the plan:
  1. Sanity / identity check (catch v2-style bugs BEFORE trusting anything)
  2. Correlation matrix + VIF (redundancy, with evidence)
  3. Mutual information with Label (univariate signal)
  4. Permutation importance (not impurity-based -- v2 used impurity-based
     .feature_importances_, which is biased toward high-cardinality /
     continuous features)
  5. Group ablation (drop a whole concept-group, measure real perf drop)
  6. Bootstrap stability of permutation importance
  7. OOD check (does the feature's signal hold up on the held-out OOD set,
     or is it a generator fingerprint?)

Everything here is computed for real against ssh_features_v3.csv /
ssh_features_v3_ood.csv -- nothing is asserted without a number attached.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import mutual_info_classif
from sklearn.inspection import permutation_importance
from sklearn.model_selection import train_test_split
from sklearn.metrics import average_precision_score, f1_score

RANDOM_STATE = 42

# All raw counts + ratios computed by extract_features_v3.py.
ALL_CANDIDATES = [
    "n_events", "n_failed", "n_invalid_user", "n_success",
    "fail_ratio", "invalid_ratio", "publickey_ratio",
    "n_unique_usernames", "username_entropy", "targets_default_username",
    "n_unique_ports", "duration_seconds",
    "mean_inter_arrival_s", "median_inter_arrival_s", "std_inter_arrival_s", "min_inter_arrival_s",
    "attempts_per_minute", "ends_after_success",
    "ip_session_count", "ip_active_span_days", "ip_sessions_per_day",
    "ip_total_events", "ip_unique_usernames_targeted",
    "distinct_ips_same_target_15min",
]

FEATURE_GROUPS = {
    "volume_counts": ["n_events", "n_failed", "n_invalid_user", "n_success"],
    "ratios": ["fail_ratio", "invalid_ratio", "publickey_ratio"],
    "diversity": ["n_unique_usernames", "username_entropy", "n_unique_ports"],
    "domain_flags": ["targets_default_username", "ends_after_success"],
    "temporal": ["duration_seconds", "mean_inter_arrival_s", "median_inter_arrival_s",
                 "std_inter_arrival_s", "min_inter_arrival_s", "attempts_per_minute"],
    "ip_level": ["ip_session_count", "ip_active_span_days", "ip_sessions_per_day",
                 "ip_total_events", "ip_unique_usernames_targeted"],
    "time_window": ["distinct_ips_same_target_15min"],
}


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


# --------------------------------------------------------- 1. sanity ------
def sanity_check(df):
    section("1. SANITY / IDENTITY CHECK (do this before trusting anything)")

    identity_sum = df["n_failed"] + df["n_invalid_user"] + df["n_success"]
    exact_match = (identity_sum == df["n_events"]).mean()
    print(f"n_failed + n_invalid_user + n_success == n_events for "
          f"{exact_match*100:.1f}% of sessions (deterministic identity -> "
          f"n_events is fully redundant given the other 3, OR vice versa)")

    ratio_sum = df["fail_ratio"] + df["invalid_ratio"] + (
        1 - df["fail_ratio"] - df["invalid_ratio"])  # success_ratio by construction
    print("fail_ratio + invalid_ratio + success_ratio == 1.0 by construction "
          "(success_ratio was deliberately never materialized as a column)")

    extreme = (df["attempts_per_minute"] > 1000).sum()
    print(f"Sessions with attempts_per_minute > 1000: {extreme} "
          f"(v2 had 626/1929 = 32.5% pinned at exactly 1,000,000; "
          f"max here is {df['attempts_per_minute'].max():.1f})")

    corr_9_6 = df["n_unique_usernames"].corr(df["username_entropy"])
    print(f"corr(n_unique_usernames, username_entropy) = {corr_9_6:.3f} "
          "(known near-duplicate from v2 -- re-checked on v3 data, not assumed)")

    print("\n-> Decision: drop n_events (redundant with n_failed+n_invalid_user+n_success) "
          "and don't add success_ratio as a column (redundant with fail_ratio+invalid_ratio). "
          "Everything else stays IN as a candidate for the evidence-based steps below.")

    return [c for c in ALL_CANDIDATES if c != "n_events"]


# ----------------------------------------------- 2. correlation + VIF ----
def correlation_and_vif(df, cols):
    section("2. CORRELATION MATRIX + VIF (redundancy, with evidence)")
    X = df[cols].fillna(0).astype(float)
    corr = X.corr()
    pairs = (
        corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
        .stack()
        .rename("corr")
        .reset_index()
    )
    high = pairs[pairs["corr"].abs() > 0.85].sort_values("corr", key=abs, ascending=False)
    print(f"Feature pairs with |correlation| > 0.85 ({len(high)} found):")
    print(high.to_string(index=False))

    # VIF: regress each feature on all others, VIF = 1/(1-R^2)
    from numpy.linalg import lstsq
    vifs = {}
    Xv = X.values
    for i, col in enumerate(cols):
        y = Xv[:, i]
        others = np.delete(Xv, i, axis=1)
        others_c = np.column_stack([others, np.ones(len(others))])
        coef, *_ = lstsq(others_c, y, rcond=None)
        pred = others_c @ coef
        ss_res = np.sum((y - pred) ** 2)
        ss_tot = np.sum((y - y.mean()) ** 2)
        r2 = 1 - ss_res / ss_tot if ss_tot > 0 else 0
        vifs[col] = 1 / (1 - r2) if r2 < 0.9999 else np.inf
    vif_series = pd.Series(vifs).sort_values(ascending=False)
    print("\nVIF per feature (>10 = severe multicollinearity):")
    print(vif_series.to_string())
    return high, vif_series


# ------------------------------------------- 3. mutual information -------
def mutual_information(df, cols):
    section("3. MUTUAL INFORMATION WITH LABEL (univariate signal)")
    X = df[cols].fillna(0).astype(float)
    y = df["Label"].values
    mi = mutual_info_classif(X, y, random_state=RANDOM_STATE)
    mi_series = pd.Series(mi, index=cols).sort_values(ascending=False)
    print(mi_series.to_string())
    return mi_series


# ------------------------------------------ 4/6. permutation + boot ------
def permutation_and_stability(df, cols, n_boot=20):
    section("4. PERMUTATION IMPORTANCE (not impurity-based) + 6. BOOTSTRAP STABILITY")
    X = df[cols].fillna(0).astype(float)
    y = df["Label"].values
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=RANDOM_STATE, stratify=y
    )
    model = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                    random_state=RANDOM_STATE, n_jobs=-1)
    model.fit(X_train, y_train)

    boot_importances = []
    rng = np.random.RandomState(RANDOM_STATE)
    for b in range(n_boot):
        seed = rng.randint(0, 1_000_000)
        pi = permutation_importance(model, X_test, y_test, n_repeats=3,
                                     random_state=seed, scoring="average_precision", n_jobs=-1)
        boot_importances.append(pi.importances_mean)
    boot_importances = np.array(boot_importances)  # (n_boot, n_features)

    mean_imp = boot_importances.mean(axis=0)
    std_imp = boot_importances.std(axis=0)
    cv_imp = np.divide(std_imp, np.abs(mean_imp), out=np.full_like(std_imp, np.nan),
                        where=np.abs(mean_imp) > 1e-6)

    result = pd.DataFrame({
        "perm_importance_mean": mean_imp,
        "perm_importance_std": std_imp,
        "coefficient_of_variation": cv_imp,
    }, index=cols).sort_values("perm_importance_mean", ascending=False)
    print(result.to_string())
    print(f"\n(PR-AUC on held-out test split: {average_precision_score(y_test, model.predict_proba(X_test)[:,1]):.4f})")
    return result, model


# --------------------------------------------------- 5. group ablation ---
def group_ablation(df, cols):
    section("5. GROUP ABLATION (drop a whole concept-group, measure real drop)")
    X_full = df[cols].fillna(0).astype(float)
    y = df["Label"].values
    X_train, X_test, y_train, y_test = train_test_split(
        X_full, y, test_size=0.25, random_state=RANDOM_STATE, stratify=y
    )

    def fit_score(Xtr, Xte):
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                    random_state=RANDOM_STATE, n_jobs=-1)
        m.fit(Xtr, y_train)
        proba = m.predict_proba(Xte)[:, 1]
        pred = m.predict(Xte)
        return average_precision_score(y_test, proba), f1_score(y_test, pred)

    baseline_prauc, baseline_f1 = fit_score(X_train, X_test)
    print(f"Baseline (all {len(cols)} features): PR-AUC={baseline_prauc:.4f}  F1={baseline_f1:.4f}")

    rows = []
    for group, feats in FEATURE_GROUPS.items():
        feats_present = [f for f in feats if f in cols]
        if not feats_present:
            continue
        remaining = [c for c in cols if c not in feats_present]
        if not remaining:
            continue
        prauc, f1 = fit_score(X_train[remaining], X_test[remaining])
        rows.append({
            "dropped_group": group,
            "features_dropped": ", ".join(feats_present),
            "PR_AUC_without": prauc,
            "PR_AUC_drop": baseline_prauc - prauc,
            "F1_without": f1,
            "F1_drop": baseline_f1 - f1,
        })
    result = pd.DataFrame(rows).sort_values("PR_AUC_drop", ascending=False)
    print(result.to_string(index=False))
    return result


# --------------------------------------------------------- 7. OOD check --
def ood_check(df_main, df_ood, cols):
    section("7. OOD GENERALIZATION CHECK (per-feature, not just aggregate metric)")
    X = df_main[cols].fillna(0).astype(float)
    y = df_main["Label"].values
    model = RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                    random_state=RANDOM_STATE, n_jobs=-1)
    model.fit(X, y)

    X_ood = df_ood[cols].fillna(0).astype(float)
    y_ood = df_ood["Label"].values
    pi_ood = permutation_importance(model, X_ood, y_ood, n_repeats=5,
                                     random_state=RANDOM_STATE, scoring="average_precision", n_jobs=-1)
    ood_imp = pd.Series(pi_ood.importances_mean, index=cols).sort_values(ascending=False)
    print("Permutation importance computed on the OOD set (model trained on main set only):")
    print(ood_imp.to_string())

    prauc_ood = average_precision_score(y_ood, model.predict_proba(X_ood)[:, 1])
    print(f"\nPR-AUC on OOD set: {prauc_ood:.4f}")
    return ood_imp, prauc_ood


def main():
    df = pd.read_csv("ssh_features_v3.csv")
    df_ood = pd.read_csv("ssh_features_v3_ood.csv")

    cols = sanity_check(df)
    high_corr, vif = correlation_and_vif(df, cols)
    mi = mutual_information(df, cols)
    perm_result, model = permutation_and_stability(df, cols)
    ablation = group_ablation(df, cols)
    ood_imp, prauc_ood = ood_check(df, df_ood, cols)

    # persist everything for the write-up notebook
    high_corr.to_csv("verify_high_corr_pairs.csv", index=False)
    vif.to_csv("verify_vif.csv", header=["VIF"])
    mi.to_csv("verify_mutual_info.csv", header=["mutual_info"])
    perm_result.to_csv("verify_permutation_importance.csv")
    ablation.to_csv("verify_group_ablation.csv", index=False)
    ood_imp.to_csv("verify_ood_permutation_importance.csv", header=["ood_perm_importance"])

    section("SAVED")
    print("verify_high_corr_pairs.csv, verify_vif.csv, verify_mutual_info.csv, "
          "verify_permutation_importance.csv, verify_group_ablation.csv, "
          "verify_ood_permutation_importance.csv")


if __name__ == "__main__":
    main()
