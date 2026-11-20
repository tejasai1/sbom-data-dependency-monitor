from __future__ import annotations

import re
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")


# =========================================================
# 1. SETTINGS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "reports" / "sergey_dataset.xlsx"
OUTPUT_DIR = BASE_DIR / "reports"
RANDOM_STATE = 42
DEFAULT_CLUSTERS = 3

os.makedirs(OUTPUT_DIR, exist_ok=True)


# =========================================================
# 2. HELPER FUNCTIONS
# =========================================================

def standardize_column_name(col):
    col = str(col).strip().lower()
    col = re.sub(r"[^\w\s]", "_", col)
    col = re.sub(r"\s+", "_", col)
    col = re.sub(r"_+", "_", col)
    return col.strip("_")


def detect_main_sheet(excel_file):
    xls = pd.ExcelFile(excel_file)
    best_sheet = None
    best_df = None
    best_score = -1

    for sheet in xls.sheet_names:
        try:
            temp = pd.read_excel(excel_file, sheet_name=sheet)
            score = temp.shape[0] * max(temp.shape[1], 1)
            if score > best_score:
                best_score = score
                best_sheet = sheet
                best_df = temp.copy()
        except Exception:
            continue

    return best_sheet, best_df


def map_possible_columns(df):
    cols = list(df.columns)

    def find_col(options):
        for c in cols:
            for opt in options:
                if opt in c:
                    return c
        return None

    return {
        "repo": find_col(["repo", "repository", "project", "source"]),
        "package": find_col(["package", "package_name", "dependency", "component", "name"]),
        "version": find_col(["version"]),
        "scan_time": find_col(["scan_time", "scanned_at", "scan_date", "scan_timestamp", "timestamp", "created_at", "date"]),
        "severity": find_col(["severity", "cvss_severity", "risk_level"]),
        "vuln_id": find_col(["vuln", "cve", "advisory", "ghsa", "number_of_vulnerabilities", "vulnerability_count"]),
        "direct_flag": find_col(["direct", "is_direct"]),
        "transitive_flag": find_col(["transitive", "is_transitive"]),
    }


def classify_repo_source(repo_value):
    if pd.isna(repo_value):
        return "unknown"

    repo_str = str(repo_value).strip().lower()

    if "github.com" in repo_str:
        return "github"
    if repo_str.startswith("http://") or repo_str.startswith("https://"):
        return "url_other"
    if "/" in repo_str or "\\" in repo_str or ":" in repo_str:
        return "local_or_path"
    return "other"


def semver_category(version):
    if pd.isna(version):
        return "missing"

    v = str(version).strip()
    if v == "":
        return "missing"

    semver_pattern = r"^\d+\.\d+\.\d+([\-+][A-Za-z0-9\.\-]+)?$"
    simple_pattern = r"^\d+(\.\d+){0,3}$"

    if re.match(semver_pattern, v):
        return "semver_like"
    if re.match(simple_pattern, v):
        return "numeric_like"
    return "non_standard"


def safe_to_datetime(series):
    return pd.to_datetime(series, errors="coerce")


def yes_no_to_binary(val):
    if pd.isna(val):
        return np.nan

    s = str(val).strip().lower()
    if s in ["1", "true", "yes", "y", "direct"]:
        return 1
    if s in ["0", "false", "no", "n", "transitive"]:
        return 0
    return np.nan


def save_histogram(series, title, xlabel, filename, bins=30):
    plt.figure(figsize=(8, 5))
    plt.hist(series.dropna(), bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / filename, dpi=150)
    plt.close()


def save_scatter(x, y, title, xlabel, ylabel, filename):
    plt.figure(figsize=(8, 5))
    plt.scatter(x, y, alpha=0.7)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / filename, dpi=150)
    plt.close()


def save_bar(labels, values, title, xlabel, ylabel, filename, rotate=False):
    plt.figure(figsize=(10, 6))
    plt.bar(labels, values)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    if rotate:
        plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / filename, dpi=150)
    plt.close()


def save_boxplot(series, title, ylabel, filename):
    plt.figure(figsize=(8, 5))
    plt.boxplot(series.dropna())
    plt.title(title)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / filename, dpi=150)
    plt.close()


def build_data_dictionary(df, descriptions):
    rows = []
    for col in df.columns:
        example = "" if df[col].dropna().empty else str(df[col].dropna().iloc[0])
        rows.append({
            "field_name": col,
            "data_type": str(df[col].dtype),
            "description": descriptions.get(col, "Original or derived field used in analysis."),
            "example_value": example
        })
    return pd.DataFrame(rows)


def detect_outliers_iqr(series):
    s = series.dropna()
    if len(s) < 5:
        return pd.Series([False] * len(series), index=series.index)

    q1 = s.quantile(0.25)
    q3 = s.quantile(0.75)
    iqr = q3 - q1

    lower = q1 - 1.5 * iqr
    upper = q3 + 1.5 * iqr

    return (series < lower) | (series > upper)


# =========================================================
# 3. LOAD DATA
# =========================================================

print("Loading Excel file...")
sheet_name, raw_df = detect_main_sheet(INPUT_FILE)

if raw_df is None or raw_df.empty:
    raise ValueError(f"Could not read a usable sheet from the Excel file: {INPUT_FILE}")

print(f"Using sheet: {sheet_name}")
print(f"Raw shape: {raw_df.shape}")

raw_df.columns = [standardize_column_name(c) for c in raw_df.columns]
raw_df = raw_df.dropna(how="all").dropna(axis=1, how="all").copy()

print(f"Shape after removing empty rows/columns: {raw_df.shape}")


# =========================================================
# 4. DETECT IMPORTANT COLUMNS
# =========================================================

mapping = map_possible_columns(raw_df)

print("\nDetected columns:")
for k, v in mapping.items():
    print(f"  {k}: {v}")

rename_map = {}
for standard_name, detected_name in mapping.items():
    if detected_name is not None and detected_name != standard_name:
        rename_map[detected_name] = standard_name

df = raw_df.rename(columns=rename_map).copy()

for needed_col in ["repo", "package", "version", "scan_time", "severity", "vuln_id", "direct_flag", "transitive_flag"]:
    if needed_col not in df.columns:
        df[needed_col] = np.nan


# =========================================================
# 5. BASIC CLEANING
# =========================================================

print("\nCleaning data...")

for col in df.columns:
    if df[col].dtype == "object":
        df[col] = df[col].astype(str).str.strip()
        df[col] = df[col].replace({"nan": np.nan, "None": np.nan, "": np.nan})

df["scan_time"] = safe_to_datetime(df["scan_time"])
df["direct_flag"] = df["direct_flag"].apply(yes_no_to_binary)
df["transitive_flag"] = df["transitive_flag"].apply(yes_no_to_binary)

if "severity" in df.columns:
    df["severity"] = df["severity"].astype("string").fillna("").str.lower().str.strip()
    df["severity"] = df["severity"].replace({
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low"
    })

before_dupes = len(df)
df = df.drop_duplicates().copy()
after_dupes = len(df)

print(f"Removed exact duplicates: {before_dupes - after_dupes}")


# =========================================================
# 6. DERIVED RECORD-LEVEL FEATURES
# =========================================================

print("\nCreating derived record-level features...")

df["repo_source_type"] = df["repo"].apply(classify_repo_source)
df["version_category"] = df["version"].apply(semver_category)

if "vuln_id" in df.columns and pd.api.types.is_numeric_dtype(df["vuln_id"]):
    df["vuln_count"] = pd.to_numeric(df["vuln_id"], errors="coerce").fillna(0)
    df["is_vulnerable"] = (df["vuln_count"] > 0).astype(int)
else:
    vuln_numeric = pd.to_numeric(df["vuln_id"], errors="coerce")
    if vuln_numeric.notna().sum() > 0:
        df["vuln_count"] = vuln_numeric.fillna(0)
        df["is_vulnerable"] = (df["vuln_count"] > 0).astype(int)
    else:
        df["vuln_count"] = df["vuln_id"].notna().astype(int)
        df["is_vulnerable"] = df["vuln_id"].notna().astype(int)

sev = df["severity"].fillna("").astype(str).str.lower().str.strip() if "severity" in df.columns else pd.Series([""] * len(df), index=df.index)

df["severity_critical"] = (sev == "critical").astype(int)
df["severity_high"] = (sev == "high").astype(int)
df["severity_medium"] = (sev == "medium").astype(int)
df["severity_low"] = (sev == "low").astype(int)


# =========================================================
# 7. VERSION FORMAT CHECKS
# =========================================================

print("\nChecking version consistency...")

version_report = (
    df["version_category"]
    .value_counts(dropna=False)
    .rename_axis("version_category")
    .reset_index(name="count")
)

version_examples = (
    df[["version", "version_category"]]
    .dropna()
    .drop_duplicates()
    .groupby("version_category")
    .head(20)
    .reset_index(drop=True)
)

print(version_report)


# =========================================================
# 8. REPEATED SCAN EVALUATION
# =========================================================

print("\nEvaluating repeated scans...")

repo_scan_eval = (
    df.groupby("repo", dropna=False)
    .agg(
        record_count=("repo", "size"),
        distinct_scan_times=("scan_time", lambda x: x.nunique(dropna=True)),
        first_scan=("scan_time", "min"),
        last_scan=("scan_time", "max")
    )
    .reset_index()
)

repo_scan_eval["scan_span_days"] = (
    repo_scan_eval["last_scan"] - repo_scan_eval["first_scan"]
).dt.days

repo_scan_eval["scan_span_days"] = repo_scan_eval["scan_span_days"].fillna(0)
repo_scan_eval["has_repeated_scans"] = repo_scan_eval["distinct_scan_times"].fillna(0) > 1

repeated_summary = pd.DataFrame({
    "metric": [
        "total_repositories",
        "repositories_with_repeated_scans",
        "percentage_with_repeated_scans"
    ],
    "value": [
        repo_scan_eval["repo"].nunique(dropna=False),
        repo_scan_eval["has_repeated_scans"].sum(),
        round(repo_scan_eval["has_repeated_scans"].mean() * 100, 2)
    ]
})


# =========================================================
# 9. REPOSITORY-LEVEL AGGREGATION
# =========================================================

print("\nBuilding repository-level dataset...")

repo_features = (
    df.groupby("repo", dropna=False)
    .agg(
        repo_source_type=("repo_source_type", lambda x: x.dropna().iloc[0] if not x.dropna().empty else "unknown"),
        total_packages=("package", "size"),
        unique_packages=("package", pd.Series.nunique),
        missing_version_count=("version", lambda x: x.isna().sum()),
        semver_like_count=("version_category", lambda x: (x == "semver_like").sum()),
        numeric_like_count=("version_category", lambda x: (x == "numeric_like").sum()),
        non_standard_version_count=("version_category", lambda x: (x == "non_standard").sum()),
        total_vulns=("vuln_count", "sum"),
        direct_deps=("direct_flag", lambda x: np.nansum(x)),
        transitive_deps=("transitive_flag", lambda x: np.nansum(x)),
        scan_count=("scan_time", lambda x: x.nunique(dropna=True)),
        first_scan=("scan_time", "min"),
        last_scan=("scan_time", "max")
    )
    .reset_index()
)

repo_features["scan_span_days"] = (repo_features["last_scan"] - repo_features["first_scan"]).dt.days
repo_features["scan_span_days"] = repo_features["scan_span_days"].fillna(0)

repo_features["missing_version_rate"] = np.where(
    repo_features["total_packages"] > 0,
    repo_features["missing_version_count"] / repo_features["total_packages"],
    0
)

repo_features["direct_ratio"] = np.where(
    repo_features["total_packages"] > 0,
    repo_features["direct_deps"] / repo_features["total_packages"],
    0
)

repo_features["transitive_ratio"] = np.where(
    repo_features["total_packages"] > 0,
    repo_features["transitive_deps"] / repo_features["total_packages"],
    0
)

repo_features["vuln_density_per_100_packages"] = np.where(
    repo_features["total_packages"] > 0,
    repo_features["total_vulns"] / repo_features["total_packages"] * 100,
    0
)

repo_features["has_any_vulnerability"] = (repo_features["total_vulns"] > 0).astype(int)


# =========================================================
# 10. LOG TRANSFORM FOR SKEWED FEATURES
# =========================================================

print("\nApplying log transforms...")

skewed_cols = [
    "total_packages",
    "unique_packages",
    "total_vulns",
    "scan_count",
    "scan_span_days",
    "semver_like_count",
    "numeric_like_count",
    "non_standard_version_count",
]

for col in skewed_cols:
    if col in repo_features.columns:
        repo_features[f"log_{col}"] = np.log1p(repo_features[col])


# =========================================================
# 11. OUTLIER DETECTION
# =========================================================

print("\nDetecting outliers...")

repo_features["outlier_total_packages"] = detect_outliers_iqr(repo_features["total_packages"]).astype(int)
repo_features["outlier_total_vulns"] = detect_outliers_iqr(repo_features["total_vulns"]).astype(int)
repo_features["outlier_vuln_density"] = detect_outliers_iqr(repo_features["vuln_density_per_100_packages"]).astype(int)

repo_features["outlier_score"] = (
    repo_features["outlier_total_packages"] +
    repo_features["outlier_total_vulns"] +
    repo_features["outlier_vuln_density"]
)

repo_features["is_outlier"] = (repo_features["outlier_score"] >= 1).astype(int)

outlier_summary = pd.DataFrame({
    "metric": [
        "repositories_flagged_as_outliers",
        "pct_outliers",
        "package_outliers",
        "vulnerability_outliers",
        "vulnerability_density_outliers"
    ],
    "value": [
        int(repo_features["is_outlier"].sum()),
        round(repo_features["is_outlier"].mean() * 100, 2),
        int(repo_features["outlier_total_packages"].sum()),
        int(repo_features["outlier_total_vulns"].sum()),
        int(repo_features["outlier_vuln_density"].sum())
    ]
})


# =========================================================
# 12. HANDLE MISSING VALUES
# =========================================================

print("\nHandling missing values...")

numeric_cols = repo_features.select_dtypes(include=[np.number]).columns.tolist()
categorical_cols = repo_features.select_dtypes(exclude=[np.number]).columns.tolist()

for col in numeric_cols:
    repo_features[col] = repo_features[col].fillna(repo_features[col].median())

for col in categorical_cols:
    repo_features[col] = repo_features[col].fillna("unknown")


# =========================================================
# 13. MODELING FEATURES
# =========================================================

print("\nPreparing clustering features...")

clustering_features = [
    "log_total_packages",
    "log_unique_packages",
    "missing_version_rate",
    "log_semver_like_count",
    "log_numeric_like_count",
    "log_non_standard_version_count",
    "log_total_vulns",
    "direct_ratio",
    "transitive_ratio",
    "log_scan_count",
    "log_scan_span_days",
    "vuln_density_per_100_packages"
]

clustering_features = [c for c in clustering_features if c in repo_features.columns]

model_df = repo_features[["repo"] + clustering_features].copy()

scaler = StandardScaler()
scaled_array = scaler.fit_transform(model_df[clustering_features])

scaled_df = pd.DataFrame(
    scaled_array,
    columns=[f"{c}_z" for c in clustering_features]
)

repo_model_ready = pd.concat([repo_features.reset_index(drop=True), scaled_df], axis=1)

z_cols = [f"{c}_z" for c in clustering_features]
X = repo_model_ready[z_cols].copy()


# =========================================================
# 14. ELBOW METHOD
# =========================================================

print("\nRunning elbow method...")

max_k = min(8, len(X))
inertias = []
k_values = []

if len(X) >= 2:
    for k in range(2, max_k + 1):
        km = KMeans(n_clusters=k, random_state=RANDOM_STATE, n_init=10)
        km.fit(X)
        k_values.append(k)
        inertias.append(km.inertia_)

    if len(k_values) > 0:
        plt.figure(figsize=(8, 5))
        plt.plot(k_values, inertias, marker="o")
        plt.title("Elbow Method for KMeans")
        plt.xlabel("Number of Clusters (k)")
        plt.ylabel("Inertia")
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / "eda_elbow_method.png", dpi=150)
        plt.close()


# =========================================================
# 15. KMEANS CLUSTERING
# =========================================================

print("\nRunning clustering...")

n_clusters = DEFAULT_CLUSTERS
if len(X) < n_clusters:
    n_clusters = max(1, len(X))

if len(X) >= 2 and n_clusters > 1:
    kmeans = KMeans(n_clusters=n_clusters, random_state=RANDOM_STATE, n_init=10)
    repo_model_ready["cluster"] = kmeans.fit_predict(X)
else:
    repo_model_ready["cluster"] = 0

cluster_summary = (
    repo_model_ready.groupby("cluster")
    .agg(
        repository_count=("repo", "size"),
        avg_total_packages=("total_packages", "mean"),
        avg_total_vulns=("total_vulns", "mean"),
        avg_missing_version_rate=("missing_version_rate", "mean"),
        avg_vuln_density=("vuln_density_per_100_packages", "mean"),
        avg_outlier_score=("outlier_score", "mean")
    )
    .reset_index()
)


# =========================================================
# 16. PCA FOR VISUALIZATION
# =========================================================

print("\nCreating PCA projection...")

if len(X) >= 2 and X.shape[1] >= 2:
    pca = PCA(n_components=2, random_state=RANDOM_STATE)
    pca_coords = pca.fit_transform(X)
    repo_model_ready["pca_1"] = pca_coords[:, 0]
    repo_model_ready["pca_2"] = pca_coords[:, 1]
else:
    repo_model_ready["pca_1"] = 0
    repo_model_ready["pca_2"] = 0


# =========================================================
# 17. SAMPLE / TEST SPLIT
# =========================================================

print("\nCreating sample and test datasets...")

if len(repo_model_ready) >= 5:
    sample_df, test_df = train_test_split(
        repo_model_ready,
        test_size=0.30,
        random_state=RANDOM_STATE
    )
else:
    sample_df = repo_model_ready.copy()
    test_df = repo_model_ready.copy()

sample_df = sample_df.reset_index(drop=True)
test_df = test_df.reset_index(drop=True)


# =========================================================
# 18. VISUALIZATIONS
# =========================================================

print("\nGenerating visualizations...")

save_histogram(
    repo_model_ready["total_packages"],
    "Distribution of Total Packages",
    "Total Packages",
    "eda_total_packages_hist.png"
)

save_histogram(
    repo_model_ready["log_total_packages"],
    "Distribution of Log Total Packages",
    "log(1 + Total Packages)",
    "eda_log_total_packages_hist.png"
)

save_scatter(
    repo_model_ready["total_packages"],
    repo_model_ready["total_vulns"],
    "Packages vs Vulnerabilities",
    "Total Packages",
    "Total Vulnerabilities",
    "eda_packages_vs_vulns.png"
)

save_scatter(
    repo_model_ready["log_total_packages"],
    repo_model_ready["log_total_vulns"],
    "Log Packages vs Log Vulnerabilities",
    "log(1 + Total Packages)",
    "log(1 + Total Vulnerabilities)",
    "eda_log_packages_vs_log_vulns.png"
)

cluster_counts = repo_model_ready["cluster"].value_counts().sort_index()
save_bar(
    cluster_counts.index.astype(str),
    cluster_counts.values,
    "Cluster Sizes",
    "Cluster",
    "Repository Count",
    "eda_cluster_sizes.png"
)

plt.figure(figsize=(8, 5))
plt.scatter(
    repo_model_ready["pca_1"],
    repo_model_ready["pca_2"],
    c=repo_model_ready["cluster"],
    alpha=0.8
)
plt.title("PCA Projection of Repository Clusters")
plt.xlabel("PCA 1")
plt.ylabel("PCA 2")
plt.tight_layout()
plt.savefig(OUTPUT_DIR / "eda_pca_clusters.png", dpi=150)
plt.close()

save_boxplot(
    repo_model_ready["vuln_density_per_100_packages"],
    "Vulnerability Density Distribution",
    "Vulnerabilities per 100 Packages",
    "eda_vuln_density_boxplot.png"
)

top_risky = repo_model_ready.sort_values(
    by=["total_vulns", "vuln_density_per_100_packages", "total_packages"],
    ascending=[False, False, False]
).head(10)

save_bar(
    top_risky["repo"].astype(str),
    top_risky["total_vulns"],
    "Top 10 Repositories by Total Vulnerabilities",
    "Repository",
    "Total Vulnerabilities",
    "eda_top_10_risky_repos.png",
    rotate=True
)

outlier_counts = pd.Series({
    "package_outliers": int(repo_model_ready["outlier_total_packages"].sum()),
    "vulnerability_outliers": int(repo_model_ready["outlier_total_vulns"].sum()),
    "density_outliers": int(repo_model_ready["outlier_vuln_density"].sum())
})

save_bar(
    outlier_counts.index,
    outlier_counts.values,
    "Outlier Counts by Type",
    "Outlier Type",
    "Count",
    "eda_outlier_counts.png"
)

cluster_profile_plot = cluster_summary.copy()
cluster_profile_plot["cluster"] = cluster_profile_plot["cluster"].astype(str)

save_bar(
    cluster_profile_plot["cluster"],
    cluster_profile_plot["avg_total_vulns"],
    "Average Vulnerabilities by Cluster",
    "Cluster",
    "Average Total Vulnerabilities",
    "eda_avg_vulns_by_cluster.png"
)


# =========================================================
# 19. DATA DICTIONARY
# =========================================================

print("\nBuilding data dictionary...")

descriptions = {
    "repo": "Repository identifier used to group package records.",
    "package": "Package or dependency name from the SBOM scan.",
    "version": "Package version string.",
    "scan_time": "Scan timestamp for the record.",
    "severity": "Severity level when available.",
    "vuln_id": "Original vulnerability-related field from the input dataset.",
    "vuln_count": "Numeric vulnerability count per record.",
    "repo_source_type": "Classifies repository source as GitHub, URL, local path, or other.",
    "version_category": "Version format category: semver-like, numeric-like, non-standard, or missing.",
    "is_vulnerable": "Binary flag showing whether the record has one or more vulnerabilities.",
    "severity_critical": "Binary flag for critical severity.",
    "severity_high": "Binary flag for high severity.",
    "severity_medium": "Binary flag for medium severity.",
    "severity_low": "Binary flag for low severity.",
    "total_packages": "Total package records for the repository.",
    "unique_packages": "Distinct packages found in the repository.",
    "missing_version_count": "Number of package records missing version values.",
    "missing_version_rate": "Share of package records with missing version values.",
    "semver_like_count": "Count of semver-like versions.",
    "numeric_like_count": "Count of numeric-like versions.",
    "non_standard_version_count": "Count of non-standard version values.",
    "total_vulns": "Total vulnerability count aggregated for the repository.",
    "direct_deps": "Count of direct dependencies when available.",
    "transitive_deps": "Count of transitive dependencies when available.",
    "direct_ratio": "Direct dependencies divided by total packages.",
    "transitive_ratio": "Transitive dependencies divided by total packages.",
    "scan_count": "Number of distinct scan timestamps for a repository.",
    "scan_span_days": "Days between first and last scan.",
    "vuln_density_per_100_packages": "Vulnerabilities per 100 package records.",
    "has_any_vulnerability": "Binary flag showing whether a repository has any vulnerabilities.",
    "log_total_packages": "Log-transformed total packages.",
    "log_unique_packages": "Log-transformed unique packages.",
    "log_total_vulns": "Log-transformed total vulnerabilities.",
    "log_scan_count": "Log-transformed scan count.",
    "log_scan_span_days": "Log-transformed scan span in days.",
    "log_semver_like_count": "Log-transformed count of semver-like versions.",
    "log_numeric_like_count": "Log-transformed count of numeric-like versions.",
    "log_non_standard_version_count": "Log-transformed count of non-standard versions.",
    "outlier_total_packages": "Binary outlier flag based on total packages.",
    "outlier_total_vulns": "Binary outlier flag based on total vulnerabilities.",
    "outlier_vuln_density": "Binary outlier flag based on vulnerability density.",
    "outlier_score": "Total number of outlier rules triggered by a repository.",
    "is_outlier": "Binary flag showing whether repository was flagged as an outlier.",
    "cluster": "Assigned KMeans cluster label.",
    "pca_1": "First PCA component for visualization.",
    "pca_2": "Second PCA component for visualization.",
}

data_dictionary = build_data_dictionary(repo_model_ready, descriptions)


# =========================================================
# 20. REPEATED SCAN RECOMMENDATION
# =========================================================

repeat_pct = repeated_summary.loc[
    repeated_summary["metric"] == "percentage_with_repeated_scans", "value"
].iloc[0]

if repeat_pct < 20:
    recommendation_text = (
        "Repeated scans are limited. For unsupervised learning, one repository-level aggregated record "
        "per repository is appropriate. Keep scan history as summary features such as scan_count and scan_span_days."
    )
else:
    recommendation_text = (
        "Repeated scans are substantial. Compare latest-scan filtering against repository-level aggregation "
        "and evaluate cluster stability across both approaches."
    )

recommendation_df = pd.DataFrame({
    "recommendation": [recommendation_text]
})


# =========================================================
# 21. SAVE OUTPUTS
# =========================================================

print("\nSaving outputs...")

excel_output = OUTPUT_DIR / "sbom_analysis_results.xlsx"
sample_excel = OUTPUT_DIR / "sbom_sample_data.xlsx"
test_excel = OUTPUT_DIR / "sbom_test_data.xlsx"
sample_csv = OUTPUT_DIR / "sbom_sample_data.csv"
test_csv = OUTPUT_DIR / "sbom_test_data.csv"

with pd.ExcelWriter(excel_output, engine="xlsxwriter") as writer:
    df.to_excel(writer, sheet_name="Raw_Cleaned", index=False)
    repo_features.to_excel(writer, sheet_name="Repo_Features", index=False)
    repo_model_ready.to_excel(writer, sheet_name="Repo_Model_Ready", index=False)
    version_report.to_excel(writer, sheet_name="Version_Report", index=False)
    version_examples.to_excel(writer, sheet_name="Version_Examples", index=False)
    repo_scan_eval.to_excel(writer, sheet_name="Repeated_Scan_Eval", index=False)
    repeated_summary.to_excel(writer, sheet_name="Repeated_Scan_Summary", index=False)
    recommendation_df.to_excel(writer, sheet_name="Recommendation", index=False)
    cluster_summary.to_excel(writer, sheet_name="Cluster_Summary", index=False)
    outlier_summary.to_excel(writer, sheet_name="Outlier_Summary", index=False)
    top_risky.to_excel(writer, sheet_name="Top_Risky_Repos", index=False)
    data_dictionary.to_excel(writer, sheet_name="Data_Dictionary", index=False)

sample_df.to_excel(sample_excel, index=False)
test_df.to_excel(test_excel, index=False)
sample_df.to_csv(sample_csv, index=False)
test_df.to_csv(test_csv, index=False)

print(f"Main Excel output saved to: {excel_output}")
print(f"Sample Excel saved to: {sample_excel}")
print(f"Test Excel saved to: {test_excel}")
print(f"Sample CSV saved to: {sample_csv}")
print(f"Test CSV saved to: {test_csv}")
print("\nDone.")