"""Collect impact facts for one repository from the capstone's MySQL database.

These facts are the only information the LLM is allowed to use."""
import json
import sys
from pathlib import Path
import re

import pymysql

# The database settings live in sbom-tools/tejasai_db_config.py
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sbom-tools"))
from tejasai_db_config import DB_CONFIG  # noqa: E402

SEVERITIES = ("critical", "high", "medium", "low")
MAX_DEPTH = 10  # stop following links after 10 hops


def short_name(target_id):
    """https://github.com/keycloak/keycloak -> keycloak/keycloak
    C:\\flowtrace-demos\\robot-shop\\cart -> robot-shop/cart"""
    t = target_id.rstrip("/\\")
    if t.endswith(".git"):
        t = t[:-4]
    parts = [p for p in re.split(r"[\\/]+", t) if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else t

def _cursor(conn):
    return conn.cursor(pymysql.cursors.DictCursor)


def load_targets(conn):
    with _cursor(conn) as cur:
        cur.execute("SELECT target_pk, target_id FROM monitored_targets")
        return {r["target_pk"]: r["target_id"] for r in cur.fetchall()}


def load_links(conn):
    with _cursor(conn) as cur:
        cur.execute("SELECT source_target_pk, dest_target_pk, data_type, description "
                    "FROM data_dependency")
        return cur.fetchall()


def latest_scan_id(conn, target_id):
    with _cursor(conn) as cur:
        cur.execute("SELECT MAX(scan_id) AS s FROM scan WHERE target_id = %s", (target_id,))
        row = cur.fetchone()
        return row["s"] if row else None


def vuln_summary(conn, target_id, top=3):
    """Counts by severity (same method as the dashboard) and the most serious findings."""
    scan_id = latest_scan_id(conn, target_id)
    counts = {s: 0 for s in SEVERITIES}
    summary = {"scan_id": scan_id, "scanned": scan_id is not None,
               "total": 0, "by_severity": counts, "most_serious": []}
    if scan_id is None:
        return summary
    with _cursor(conn) as cur:
        cur.execute("""
            SELECT LOWER(COALESCE(v.severity, 'unknown')) AS sev,
                   COUNT(DISTINCT o.package_id, o.vulnerability_id) AS c
            FROM package_vuln_observation o
            JOIN vulnerability v ON o.vulnerability_id = v.vulnerability_id
            WHERE o.scan_id = %s
            GROUP BY sev""", (scan_id,))
        for r in cur.fetchall():
            summary["total"] += int(r["c"])
            if r["sev"] in counts:
                counts[r["sev"]] = int(r["c"])
        cur.execute("""
            SELECT v.cve_id, v.severity, pn.package_name, pn.version, o.fixed_version
            FROM package_vuln_observation o
            JOIN vulnerability v ON o.vulnerability_id = v.vulnerability_id
            JOIN packages_name pn ON o.package_id = pn.package_id
            WHERE o.scan_id = %s AND LOWER(v.severity) IN ('critical', 'high')
            ORDER BY FIELD(LOWER(v.severity), 'critical', 'high'), v.cve_id""", (scan_id,))
        grouped = {}
        for r in cur.fetchall():
            entry = grouped.setdefault(r["cve_id"], {
                "id": r["cve_id"], "severity": r["severity"].lower(),
                "packages": [], "fixed_in": []})
            pkg = f"{r['package_name']} {r['version']}"
            if pkg not in entry["packages"]:
                entry["packages"].append(pkg)
            fix = (r["fixed_version"] or "").strip()
            if fix and fix not in entry["fixed_in"]:
                entry["fixed_in"].append(fix)
        summary["most_serious"] = [
            {**e, "packages": e["packages"][:3],
             "fixed_in": e["fixed_in"][:3] or ["no fix listed"]}
            for e in list(grouped.values())[:top]]
    return summary


def walk(start, links, direction):
    """Follow links level by level. Returns the links used and each system reached with its hop count."""
    nxt = {}
    for link in links:
        a, b = link["source_target_pk"], link["dest_target_pk"]
        if direction == "up":
            a, b = b, a
        nxt.setdefault(a, []).append(b)
    used, reached, seen, frontier, depth = [], [], {start}, [start], 0
    while frontier and depth < MAX_DEPTH:
        depth += 1
        new = []
        for a in frontier:
            for b in sorted(nxt.get(a, [])):
                used.append((a, b) if direction == "down" else (b, a))
                if b not in seen:  # loops stop here
                    seen.add(b)
                    reached.append((b, depth))
                    new.append(b)
        frontier = new
    return used, reached


def build_facts(name):
    """name: 'keycloak/keycloak', the full GitHub URL, or the target_pk number."""
    conn = pymysql.connect(**DB_CONFIG)
    try:
        targets = load_targets(conn)
        start = next((pk for pk, tid in targets.items()
                      if name in (str(pk), tid, short_name(tid))), None)
        if start is None:
            raise ValueError(f"Repository not found: {name}")
        links = load_links(conn)
        label = {pk: short_name(tid) for pk, tid in targets.items()}
        info = {(l["source_target_pk"], l["dest_target_pk"]): l for l in links}

        facts = {"target_pk": start, "system": label[start],
                 "vulnerabilities": vuln_summary(conn, targets[start], top=5),
                 "downstream": [], "upstream": [], "data_flows": []}
        flow_keys = set()
        for direction in ("down", "up"):
            used, reached = walk(start, links, direction)
            for pk, hops in reached:
                facts[direction + "stream"].append(
                    {"system": label[pk], "hops": hops,
                     "vulnerabilities": vuln_summary(conn, targets[pk])})
            flow_keys.update(used)
        for a, b in sorted(flow_keys, key=lambda k: (label[k[0]], label[k[1]])):
            l = info.get((a, b), {})
            flow = {"from": label[a], "to": label[b]}
            if l.get("data_type"):
                flow["data_type"] = l["data_type"]
            if l.get("description"):
                flow["description"] = l["description"]
            facts["data_flows"].append(flow)
        return facts
    finally:
        conn.close()


if __name__ == "__main__":
    print(json.dumps(build_facts(sys.argv[1]), indent=2, default=str))