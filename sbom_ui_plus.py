from __future__ import annotations

import textwrap
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LinearRegression
from sklearn.metrics import accuracy_score, mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split

# =========================================================
# SETTINGS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "reports" / "sbom_analysis_results.xlsx"
OUTPUT_DIR = BASE_DIR / "ui" / "static" / "dashboard_plus"
RANDOM_STATE = 42

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# =========================================================
# LOAD DATA
# =========================================================

repo_df = pd.read_excel(INPUT_FILE, sheet_name="Repo_Model_Ready").copy()

# =========================================================
# HELPERS
# =========================================================

def short_repo_name(repo):
    if pd.isna(repo):
        return "unknown"
    repo = str(repo)
    repo = repo.replace("https://github.com/", "")
    repo = repo.replace("http://github.com/", "")
    return textwrap.shorten(repo, width=30, placeholder="...")

def save_html(fig, filename):
    fig.write_html(str(OUTPUT_DIR / filename), include_plotlyjs="cdn")

def safe_numeric_columns(df, cols):
    return [c for c in cols if c in df.columns and pd.api.types.is_numeric_dtype(df[c])]

# =========================================================
# PREP
# =========================================================

repo_df["repo_short"] = repo_df["repo"].apply(short_repo_name)

repo_df["risk_segment"] = pd.cut(
    repo_df["total_vulns"],
    bins=[-1, 0, 100, 1000, np.inf],
    labels=["No Known Risk", "Low Risk", "Medium Risk", "High Risk"]
)

repo_df["size_segment"] = pd.cut(
    repo_df["total_packages"],
    bins=[-1, 100, 500, 2000, np.inf],
    labels=["Small", "Medium", "Large", "Very Large"]
)

repo_df["is_high_risk"] = (
    (repo_df["total_vulns"] >= repo_df["total_vulns"].quantile(0.80)) |
    (repo_df["vuln_density_per_100_packages"] >= repo_df["vuln_density_per_100_packages"].quantile(0.80))
).astype(int)

# =========================================================
# KPI SUMMARY
# =========================================================

kpi = {
    "total_repositories": int(repo_df["repo"].nunique()),
    "total_packages": int(repo_df["total_packages"].sum()),
    "total_vulnerabilities": int(repo_df["total_vulns"].sum()),
    "avg_vuln_density": round(repo_df["vuln_density_per_100_packages"].mean(), 2),
    "outlier_count": int(repo_df["is_outlier"].sum()) if "is_outlier" in repo_df.columns else 0,
    "high_risk_repositories": int(repo_df["is_high_risk"].sum()),
}

pd.DataFrame({
    "metric": list(kpi.keys()),
    "value": list(kpi.values())
}).to_csv(OUTPUT_DIR / "kpi_summary.csv", index=False)

# =========================================================
# 1. TOP RISKY REPOSITORIES
# =========================================================

top_risky = (
    repo_df.sort_values(
        by=["total_vulns", "vuln_density_per_100_packages", "total_packages"],
        ascending=[False, False, False]
    )
    .head(10)
    .copy()
)

fig_top_risky = px.bar(
    top_risky,
    x="total_vulns",
    y="repo_short",
    orientation="h",
    text="total_vulns",
    hover_data=["repo", "total_packages", "vuln_density_per_100_packages", "cluster"],
    title="Top 10 Repositories by Vulnerability Count"
)
fig_top_risky.update_layout(
    template="plotly_white",
    height=500,
    yaxis_title="Repository",
    xaxis_title="Total Vulnerabilities"
)
fig_top_risky.update_traces(textposition="outside")
fig_top_risky.update_yaxes(categoryorder="total ascending")
save_html(fig_top_risky, "top_risky_repositories.html")

# =========================================================
# 2. TOP VULNERABILITY DENSITY
# =========================================================

top_density = (
    repo_df[repo_df["total_packages"] > 0]
    .sort_values(by="vuln_density_per_100_packages", ascending=False)
    .head(10)
    .copy()
)

fig_top_density = px.bar(
    top_density,
    x="vuln_density_per_100_packages",
    y="repo_short",
    orientation="h",
    text="vuln_density_per_100_packages",
    hover_data=["repo", "total_packages", "total_vulns"],
    title="Top 10 Repositories by Vulnerability Density"
)
fig_top_density.update_layout(
    template="plotly_white",
    height=500,
    yaxis_title="Repository",
    xaxis_title="Vulnerabilities per 100 Packages"
)
fig_top_density.update_traces(textposition="outside")
fig_top_density.update_yaxes(categoryorder="total ascending")
save_html(fig_top_density, "top_vulnerability_density.html")

# =========================================================
# 3. TOP PACKAGE COUNT
# =========================================================

top_packages = repo_df.sort_values(by="total_packages", ascending=False).head(10).copy()

fig_top_packages = px.bar(
    top_packages,
    x="total_packages",
    y="repo_short",
    orientation="h",
    text="total_packages",
    hover_data=["repo", "total_vulns", "vuln_density_per_100_packages"],
    title="Top 10 Repositories by Package Count"
)
fig_top_packages.update_layout(
    template="plotly_white",
    height=500,
    yaxis_title="Repository",
    xaxis_title="Total Packages"
)
fig_top_packages.update_traces(textposition="outside")
fig_top_packages.update_yaxes(categoryorder="total ascending")
save_html(fig_top_packages, "top_package_count.html")

# =========================================================
# 4. BUBBLE CHART
# =========================================================

fig_bubble = px.scatter(
    repo_df,
    x="total_packages",
    y="total_vulns",
    size="vuln_density_per_100_packages",
    color="risk_segment",
    hover_name="repo_short",
    hover_data=["repo", "cluster", "total_packages", "total_vulns", "vuln_density_per_100_packages"],
    title="Repository Size vs Vulnerability Burden",
    size_max=35
)
fig_bubble.update_layout(
    template="plotly_white",
    height=550,
    xaxis_title="Total Packages",
    yaxis_title="Total Vulnerabilities"
)
save_html(fig_bubble, "packages_vs_vulnerabilities_bubble.html")

# =========================================================
# 5. CLUSTER DONUT
# =========================================================

cluster_counts = repo_df["cluster"].value_counts().sort_index().reset_index()
cluster_counts.columns = ["cluster", "count"]

fig_cluster_donut = px.pie(
    cluster_counts,
    names="cluster",
    values="count",
    hole=0.55,
    title="Repository Cluster Distribution"
)
fig_cluster_donut.update_layout(template="plotly_white", height=430)
save_html(fig_cluster_donut, "cluster_distribution_donut.html")

# =========================================================
# 6. RISK SEGMENT DONUT
# =========================================================

risk_counts = repo_df["risk_segment"].value_counts(dropna=False).reset_index()
risk_counts.columns = ["risk_segment", "count"]

fig_risk_donut = px.pie(
    risk_counts,
    names="risk_segment",
    values="count",
    hole=0.55,
    title="Repository Risk Segments"
)
fig_risk_donut.update_layout(template="plotly_white", height=430)
save_html(fig_risk_donut, "risk_segment_donut.html")

# =========================================================
# 7. SIZE SEGMENT DONUT
# =========================================================

size_counts = repo_df["size_segment"].value_counts(dropna=False).reset_index()
size_counts.columns = ["size_segment", "count"]

fig_size_donut = px.pie(
    size_counts,
    names="size_segment",
    values="count",
    hole=0.55,
    title="Repository Size Segments"
)
fig_size_donut.update_layout(template="plotly_white", height=430)
save_html(fig_size_donut, "size_segment_donut.html")

# =========================================================
# 8. PCA CLUSTER MAP
# =========================================================

fig_pca = px.scatter(
    repo_df,
    x="pca_1",
    y="pca_2",
    color="cluster",
    hover_name="repo_short",
    hover_data=["repo", "total_packages", "total_vulns", "vuln_density_per_100_packages"],
    title="Cluster Map of Repositories"
)
fig_pca.update_layout(
    template="plotly_white",
    height=550,
    xaxis_title="PCA Component 1",
    yaxis_title="PCA Component 2"
)
save_html(fig_pca, "pca_cluster_map.html")

# =========================================================
# 9. VERSION QUALITY OVERVIEW
# =========================================================

version_summary = pd.DataFrame({
    "category": ["Semver-like", "Numeric-like", "Non-standard", "Missing"],
    "count": [
        repo_df["semver_like_count"].sum() if "semver_like_count" in repo_df.columns else 0,
        repo_df["numeric_like_count"].sum() if "numeric_like_count" in repo_df.columns else 0,
        repo_df["non_standard_version_count"].sum() if "non_standard_version_count" in repo_df.columns else 0,
        repo_df["missing_version_count"].sum() if "missing_version_count" in repo_df.columns else 0,
    ]
})

fig_version = px.bar(
    version_summary,
    x="category",
    y="count",
    text="count",
    title="Version Quality Overview"
)
fig_version.update_layout(
    template="plotly_white",
    height=430,
    xaxis_title="Version Category",
    yaxis_title="Count"
)
fig_version.update_traces(textposition="outside")
save_html(fig_version, "version_quality_overview.html")

# =========================================================
# 10. MISSING VERSION RATE BY REPO
# =========================================================

top_missing = repo_df.sort_values(by="missing_version_rate", ascending=False).head(10).copy()

fig_missing = px.bar(
    top_missing,
    x="missing_version_rate",
    y="repo_short",
    orientation="h",
    text="missing_version_rate",
    hover_data=["repo", "total_packages", "missing_version_count"],
    title="Top 10 Repositories by Missing Version Rate"
)
fig_missing.update_layout(
    template="plotly_white",
    height=500,
    yaxis_title="Repository",
    xaxis_title="Missing Version Rate"
)
fig_missing.update_traces(textposition="outside")
fig_missing.update_yaxes(categoryorder="total ascending")
save_html(fig_missing, "missing_version_rate.html")

# =========================================================
# 11. OUTLIER SUMMARY
# =========================================================

outlier_df = pd.DataFrame({
    "type": ["Package Outliers", "Vulnerability Outliers", "Density Outliers"],
    "count": [
        int(repo_df["outlier_total_packages"].sum()) if "outlier_total_packages" in repo_df.columns else 0,
        int(repo_df["outlier_total_vulns"].sum()) if "outlier_total_vulns" in repo_df.columns else 0,
        int(repo_df["outlier_vuln_density"].sum()) if "outlier_vuln_density" in repo_df.columns else 0,
    ]
})

fig_outliers = px.bar(
    outlier_df,
    x="type",
    y="count",
    text="count",
    title="Outlier Summary"
)
fig_outliers.update_layout(
    template="plotly_white",
    height=430,
    xaxis_title="Outlier Type",
    yaxis_title="Repository Count"
)
fig_outliers.update_traces(textposition="outside")
save_html(fig_outliers, "outlier_summary.html")

# =========================================================
# 12. CLUSTER PROFILE COMPARISON
# =========================================================

cluster_profile = (
    repo_df.groupby("cluster")
    .agg(
        avg_total_packages=("total_packages", "mean"),
        avg_total_vulns=("total_vulns", "mean"),
        avg_vuln_density=("vuln_density_per_100_packages", "mean"),
        avg_missing_version_rate=("missing_version_rate", "mean"),
        repo_count=("repo", "count")
    )
    .reset_index()
)

cluster_profile_long = cluster_profile.melt(
    id_vars=["cluster"],
    value_vars=["avg_total_packages", "avg_total_vulns", "avg_vuln_density", "avg_missing_version_rate"],
    var_name="metric",
    value_name="value"
)

fig_cluster_profile = px.bar(
    cluster_profile_long,
    x="cluster",
    y="value",
    color="metric",
    barmode="group",
    title="Cluster Profile Comparison"
)
fig_cluster_profile.update_layout(
    template="plotly_white",
    height=500,
    xaxis_title="Cluster",
    yaxis_title="Average Value"
)
save_html(fig_cluster_profile, "cluster_profile_comparison.html")

# =========================================================
# 13. CORRELATION HEATMAP
# =========================================================

corr_cols = safe_numeric_columns(repo_df, [
    "total_packages", "unique_packages", "total_vulns",
    "vuln_density_per_100_packages", "missing_version_rate",
    "scan_count", "scan_span_days"
])

if len(corr_cols) >= 2:
    corr_matrix = repo_df[corr_cols].corr()
    fig_corr = px.imshow(
        corr_matrix,
        text_auto=".2f",
        aspect="auto",
        title="Feature Correlation Heatmap"
    )
    fig_corr.update_layout(template="plotly_white", height=520)
    save_html(fig_corr, "correlation_heatmap.html")

# =========================================================
# 14. REPEATED SCAN SUMMARY
# =========================================================

if "scan_count" in repo_df.columns:
    scan_summary = repo_df["scan_count"].value_counts().sort_index().reset_index()
    scan_summary.columns = ["scan_count", "repo_count"]

    fig_scan = px.bar(
        scan_summary,
        x="scan_count",
        y="repo_count",
        text="repo_count",
        title="Repeated Scan Distribution"
    )
    fig_scan.update_layout(
        template="plotly_white",
        height=430,
        xaxis_title="Number of Distinct Scans",
        yaxis_title="Repository Count"
    )
    fig_scan.update_traces(textposition="outside")
    save_html(fig_scan, "repeated_scan_distribution.html")

# =========================================================
# 15. HIGH-RISK PREDICTION DEMO
# =========================================================

feature_cols = safe_numeric_columns(repo_df, [
    "total_packages",
    "unique_packages",
    "missing_version_rate",
    "semver_like_count",
    "numeric_like_count",
    "non_standard_version_count",
    "scan_count",
    "scan_span_days",
    "vuln_density_per_100_packages"
])

prediction_report_rows = []

if len(feature_cols) >= 3 and repo_df["is_high_risk"].nunique() > 1:
    X = repo_df[feature_cols].fillna(0)
    y = repo_df["is_high_risk"]

    X_train, X_test, y_train, y_test, repo_train, repo_test = train_test_split(
        X, y, repo_df["repo"],
        test_size=0.30,
        random_state=RANDOM_STATE,
        stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=6,
        random_state=RANDOM_STATE
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)

    prediction_report_rows.append({
        "model": "RandomForestClassifier",
        "target": "is_high_risk",
        "accuracy": round(acc, 4)
    })

    feature_importance = pd.DataFrame({
        "feature": feature_cols,
        "importance": clf.feature_importances_
    }).sort_values(by="importance", ascending=False)

    fig_importance = px.bar(
        feature_importance,
        x="importance",
        y="feature",
        orientation="h",
        text="importance",
        title="High-Risk Prediction: Feature Importance"
    )
    fig_importance.update_layout(
        template="plotly_white",
        height=500,
        xaxis_title="Importance",
        yaxis_title="Feature"
    )
    fig_importance.update_traces(texttemplate="%{text:.3f}", textposition="outside")
    fig_importance.update_yaxes(categoryorder="total ascending")
    save_html(fig_importance, "prediction_feature_importance.html")

    pred_table = pd.DataFrame({
        "repo": repo_test.values,
        "actual_high_risk": y_test.values,
        "predicted_high_risk": y_pred,
        "predicted_probability": y_prob
    }).sort_values(by="predicted_probability", ascending=False)

    pred_table.to_csv(OUTPUT_DIR / "high_risk_prediction_results.csv", index=False)
else:
    empty_fig = px.bar(
        pd.DataFrame({"feature": ["No model"], "importance": [0]}),
        x="importance",
        y="feature",
        orientation="h",
        title="High-Risk Prediction: Feature Importance"
    )
    empty_fig.update_layout(template="plotly_white", height=500)
    save_html(empty_fig, "prediction_feature_importance.html")

# =========================================================
# 16. VULNERABILITY COUNT REGRESSION DEMO
# =========================================================

regression_rows = []

if len(feature_cols) >= 3:
    X_reg = repo_df[feature_cols].fillna(0)
    y_reg = repo_df["total_vulns"].fillna(0)

    X_train_r, X_test_r, y_train_r, y_test_r = train_test_split(
        X_reg, y_reg,
        test_size=0.30,
        random_state=RANDOM_STATE
    )

    reg = LinearRegression()
    reg.fit(X_train_r, y_train_r)
    pred_reg = reg.predict(X_test_r)

    regression_rows.append({
        "model": "LinearRegression",
        "target": "total_vulns",
        "mae": round(mean_absolute_error(y_test_r, pred_reg), 4),
        "r2": round(r2_score(y_test_r, pred_reg), 4)
    })

# =========================================================
# 17. ISOLATION FOREST OUTLIER DEMO
# =========================================================

outlier_demo_cols = safe_numeric_columns(repo_df, [
    "total_packages", "total_vulns", "vuln_density_per_100_packages", "missing_version_rate"
])

if len(outlier_demo_cols) >= 2:
    iso = IsolationForest(contamination=0.08, random_state=RANDOM_STATE)
    iso_pred = iso.fit_predict(repo_df[outlier_demo_cols].fillna(0))
    repo_df["iforest_outlier"] = (iso_pred == -1).astype(int)

    iso_summary = pd.DataFrame({
        "metric": ["iforest_outliers"],
        "value": [int(repo_df["iforest_outlier"].sum())]
    })
    iso_summary.to_csv(OUTPUT_DIR / "iforest_summary.csv", index=False)

    fig_iforest = px.scatter(
        repo_df,
        x="total_packages",
        y="total_vulns",
        color="iforest_outlier",
        hover_name="repo_short",
        hover_data=["repo", "vuln_density_per_100_packages"],
        title="Isolation Forest Outlier Detection"
    )
    fig_iforest.update_layout(
        template="plotly_white",
        height=520,
        xaxis_title="Total Packages",
        yaxis_title="Total Vulnerabilities"
    )
    save_html(fig_iforest, "iforest_outlier_detection.html")
else:
    empty_iforest = px.scatter(
        pd.DataFrame({"x": [0], "y": [0]}),
        x="x",
        y="y",
        title="Isolation Forest Outlier Detection"
    )
    empty_iforest.update_layout(template="plotly_white", height=520)
    save_html(empty_iforest, "iforest_outlier_detection.html")

# =========================================================
# 18. EXPORT TABLES
# =========================================================

top_risky[[
    "repo", "total_packages", "total_vulns",
    "vuln_density_per_100_packages", "cluster", "risk_segment"
]].to_csv(OUTPUT_DIR / "top_risky_table.csv", index=False)

cluster_profile.to_csv(OUTPUT_DIR / "cluster_profile_summary.csv", index=False)
pd.DataFrame(prediction_report_rows).to_csv(OUTPUT_DIR / "prediction_summary.csv", index=False)
pd.DataFrame(regression_rows).to_csv(OUTPUT_DIR / "regression_summary.csv", index=False)

# =========================================================
# 19. DASHBOARD HTML
# =========================================================

dashboard_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SBOM Analytics + Prediction Dashboard</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            background: #f4f7fb;
            color: #1f2937;
        }}
        .container {{
            max-width: 1500px;
            margin: 0 auto;
            padding: 24px;
        }}
        .title {{
            font-size: 30px;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .subtitle {{
            color: #6b7280;
            margin-bottom: 24px;
        }}
        .cards {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: white;
            border-radius: 18px;
            padding: 18px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.08);
        }}
        .card-label {{
            font-size: 13px;
            color: #6b7280;
            margin-bottom: 8px;
        }}
        .card-value {{
            font-size: 28px;
            font-weight: 700;
        }}
        .section-title {{
            font-size: 20px;
            font-weight: 700;
            margin: 22px 0 14px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .grid-3 {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }}
        .panel {{
            background: white;
            border-radius: 18px;
            padding: 12px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.08);
        }}
        iframe {{
            width: 100%;
            height: 520px;
            border: none;
            border-radius: 12px;
        }}
        .small iframe {{
            height: 440px;
        }}
        .text-panel {{
            background: white;
            border-radius: 18px;
            padding: 22px;
            box-shadow: 0 6px 18px rgba(0,0,0,0.08);
            line-height: 1.6;
        }}
        ul {{
            padding-left: 18px;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="title">SBOM Repository Analytics + Prediction Dashboard</div>
    <div class="subtitle">Dashboard with repository analysis, clustering, outlier detection, and prediction demos for review and approval.</div>

    <div class="cards">
        <div class="card"><div class="card-label">Total Repositories</div><div class="card-value">{kpi["total_repositories"]}</div></div>
        <div class="card"><div class="card-label">Total Packages</div><div class="card-value">{kpi["total_packages"]}</div></div>
        <div class="card"><div class="card-label">Total Vulnerabilities</div><div class="card-value">{kpi["total_vulnerabilities"]}</div></div>
        <div class="card"><div class="card-label">Avg Vulnerability Density</div><div class="card-value">{kpi["avg_vuln_density"]}</div></div>
        <div class="card"><div class="card-label">Outlier Repositories</div><div class="card-value">{kpi["outlier_count"]}</div></div>
        <div class="card"><div class="card-label">High-Risk Repositories</div><div class="card-value">{kpi["high_risk_repositories"]}</div></div>
    </div>

    <div class="section-title">Overview</div>
    <div class="grid-2">
        <div class="panel"><iframe src="top_risky_repositories.html"></iframe></div>
        <div class="panel"><iframe src="packages_vs_vulnerabilities_bubble.html"></iframe></div>
    </div>

    <div class="grid-3">
        <div class="panel small"><iframe src="cluster_distribution_donut.html"></iframe></div>
        <div class="panel small"><iframe src="risk_segment_donut.html"></iframe></div>
        <div class="panel small"><iframe src="size_segment_donut.html"></iframe></div>
    </div>

    <div class="section-title">Repository Comparisons</div>
    <div class="grid-2">
        <div class="panel"><iframe src="top_vulnerability_density.html"></iframe></div>
        <div class="panel"><iframe src="top_package_count.html"></iframe></div>
    </div>

    <div class="grid-2">
        <div class="panel"><iframe src="missing_version_rate.html"></iframe></div>
        <div class="panel"><iframe src="version_quality_overview.html"></iframe></div>
    </div>

    <div class="section-title">Clustering and Patterns</div>
    <div class="grid-2">
        <div class="panel"><iframe src="pca_cluster_map.html"></iframe></div>
        <div class="panel"><iframe src="cluster_profile_comparison.html"></iframe></div>
    </div>

    <div class="section-title">Outlier Analysis</div>
    <div class="grid-2">
        <div class="panel"><iframe src="outlier_summary.html"></iframe></div>
        <div class="panel"><iframe src="iforest_outlier_detection.html"></iframe></div>
    </div>

    <div class="section-title">Prediction Demos</div>
    <div class="grid-2">
        <div class="panel"><iframe src="prediction_feature_importance.html"></iframe></div>
    </div>
</div>
</body>
</html>
"""

with open(OUTPUT_DIR / "dashboard_plus.html", "w", encoding="utf-8") as f:
    f.write(dashboard_html)

print("Done.")
print("Files created in:", OUTPUT_DIR)
print("Open this in browser:")
print(OUTPUT_DIR / "dashboard_plus.html")