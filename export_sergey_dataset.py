#!/usr/bin/env python
# coding: utf-8

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.worksheet.table import Table, TableStyleInfo
from openpyxl.utils import get_column_letter


PROJECT_ROOT = Path(__file__).resolve().parent
REPORTS_DIR = PROJECT_ROOT / "reports"
OUTPUT_FILE = REPORTS_DIR / "sergey_dataset.xlsx"


def split_node(node: str) -> tuple[str, str]:
    if "@" in node:
        name, version = node.rsplit("@", 1)
        return name, version
    return node, ""


def normalize_pkg_node(pkg_name: str, version: str) -> str:
    if version and version.lower() != "unknown":
        return f"{pkg_name}@{version}"
    return pkg_name


def severity_bucket(value: str) -> str:
    s = (value or "").strip().lower()
    if s in {"critical", "high", "medium", "low", "negligible"}:
        return s
    return ""


def auto_width(ws):
    for col_cells in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col_cells[0].column)
        for cell in col_cells:
            value = "" if cell.value is None else str(cell.value)
            if len(value) > max_len:
                max_len = len(value)
        ws.column_dimensions[col_letter].width = min(max(max_len + 2, 12), 45)


def style_sheet(ws, table_name: str):
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="1F4E78")
        c.alignment = Alignment(horizontal="center", vertical="center")
    ws.freeze_panes = "A2"

    if ws.max_row < 2:
        ws.append([""] * ws.max_column)

    ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"
    tab = Table(displayName=table_name, ref=ref)
    tab.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2",
        showRowStripes=True,
        showColumnStripes=False,
    )
    ws.add_table(tab)
    auto_width(ws)


def build_rows(report: dict) -> tuple[list[dict], list[dict], dict]:
    repo = report.get("target", "")
    scan_timestamp = report.get("timestamp", "")
    package_rows = report.get("packages", []) or []
    dependency_graph = report.get("dependency_graph", []) or []
    summary = report.get("summary", {}) or {}

    adjacency: dict[str, set[str]] = defaultdict(set)
    nodes: set[str] = set()

    for edge in dependency_graph:
        parent = str(edge.get("parent", "")).strip()
        child = str(edge.get("child", "")).strip()
        if not parent or not child or parent == "unknown" or child == "unknown":
            continue
        adjacency[parent].add(child)
        nodes.add(parent)
        nodes.add(child)

    package_info: dict[str, dict] = {}
    vulnerability_rows: list[dict] = []

    for pkg in package_rows:
        pkg_name = str(pkg.get("package", "")).strip()
        version = str(pkg.get("version", "")).strip()
        node = normalize_pkg_node(pkg_name, version)
        nodes.add(node)

        entry = package_info.setdefault(
            node,
            {
                "repo": repo,
                "scan_timestamp": scan_timestamp,
                "package_name": pkg_name,
                "version": version,
                "package_node": node,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "negligible_count": 0,
                "vulnerability_ids": [],
            },
        )

        vuln_id = str(pkg.get("vulnerability_id", "")).strip()
        severity = str(pkg.get("severity", "")).strip()
        fixed_version = str(pkg.get("fixed_version", "")).strip()

        if vuln_id and vuln_id.lower() not in {"none", "n/a", "null"}:
            bucket = severity_bucket(severity)
            if bucket:
                entry[f"{bucket}_count"] += 1
            entry["vulnerability_ids"].append(vuln_id)

            vulnerability_rows.append(
                {
                    "repo": repo,
                    "scan_timestamp": scan_timestamp,
                    "package_name": pkg_name,
                    "version": version,
                    "vulnerability_id": vuln_id,
                    "severity": severity,
                    "fixed_version": fixed_version,
                }
            )

    dataset_rows: list[dict] = []

    for node in sorted(nodes):
        first_level = set(adjacency.get(node, set()))
        second_level = set()
        for child in first_level:
            second_level.update(adjacency.get(child, set()))
        second_level.discard(node)
        second_level -= first_level

        if node in package_info:
            row = dict(package_info[node])
        else:
            pkg_name, version = split_node(node)
            row = {
                "repo": repo,
                "scan_timestamp": scan_timestamp,
                "package_name": pkg_name,
                "version": version,
                "package_node": node,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "negligible_count": 0,
                "vulnerability_ids": [],
            }

        row["num_libraries_1st_level"] = len(first_level)
        row["num_libraries_2nd_level"] = len(second_level)
        row["number_of_vulnerabilities"] = (
            row["critical_count"]
            + row["high_count"]
            + row["medium_count"]
            + row["low_count"]
            + row["negligible_count"]
        )
        row["vulnerability_ids"] = ", ".join(sorted(set(row["vulnerability_ids"])))
        dataset_rows.append(row)

    repo_summary = {
        "repo": repo,
        "scan_timestamp": scan_timestamp,
        "total_packages": summary.get("total_packages", 0),
        "total_vulnerabilities": summary.get("total_vulnerabilities", 0),
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
        "negligible": summary.get("negligible", 0),
    }

    return dataset_rows, vulnerability_rows, repo_summary


def export_sergey_dataset(
    reports_dir: Path = REPORTS_DIR,
    output_file: Path = OUTPUT_FILE,
) -> Path:
    all_dataset_rows: list[dict] = []
    all_vulnerability_rows: list[dict] = []
    all_repo_summary_rows: list[dict] = []

    for json_file in sorted(reports_dir.glob("*.json")):
        try:
            report = json.loads(json_file.read_text(encoding="utf-8"))
            dataset_rows, vulnerability_rows, repo_summary = build_rows(report)
            all_dataset_rows.extend(dataset_rows)
            all_vulnerability_rows.extend(vulnerability_rows)
            all_repo_summary_rows.append(repo_summary)
        except Exception as exc:
            print(f"[WARN] Skipping {json_file.name}: {exc}")

    wb = Workbook()

    ws1 = wb.active
    ws1.title = "Package_Dataset"
    headers1 = [
        "repo",
        "scan_timestamp",
        "package_name",
        "version",
        "package_node",
        "num_libraries_1st_level",
        "num_libraries_2nd_level",
        "number_of_vulnerabilities",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "negligible_count",
        "vulnerability_ids",
    ]
    ws1.append(headers1)
    for row in all_dataset_rows:
        ws1.append([row.get(h, "") for h in headers1])
    style_sheet(ws1, "PackageDataset")

    ws2 = wb.create_sheet("Vulnerability_Details")
    headers2 = [
        "repo",
        "scan_timestamp",
        "package_name",
        "version",
        "vulnerability_id",
        "severity",
        "fixed_version",
    ]
    ws2.append(headers2)
    for row in all_vulnerability_rows:
        ws2.append([row.get(h, "") for h in headers2])
    style_sheet(ws2, "VulnerabilityDetails")

    ws3 = wb.create_sheet("Repo_Summary")
    headers3 = [
        "repo",
        "scan_timestamp",
        "total_packages",
        "total_vulnerabilities",
        "critical",
        "high",
        "medium",
        "low",
        "negligible",
    ]
    ws3.append(headers3)
    for row in all_repo_summary_rows:
        ws3.append([row.get(h, "") for h in headers3])
    style_sheet(ws3, "RepoSummary")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output_file)
    print(f"[OK] Excel exported: {output_file}")
    return output_file


if __name__ == "__main__":
    export_sergey_dataset()