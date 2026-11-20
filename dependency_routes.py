"""
Data dependency routes.

Lets a manager record which repositories each repository gets data from,
and trace where data from a vulnerable repository flows downstream.

Registered from ui_app.py with:  register_dependency_routes(app)
Needs the data_dependency table (sql/create_data_dependency.sql).
"""
from __future__ import annotations

from collections import deque
from typing import Dict, List, Optional

import pymysql
from flask import Flask, jsonify, request

from tejasai_db_config import DB_CONFIG

MAX_TRACE_HOPS = 10
MAX_DATA_TYPE_LEN = 100
MAX_DESCRIPTION_LEN = 500


def _connect():
    return pymysql.connect(**DB_CONFIG)


def _optional_int(value) -> Optional[int]:
    if value in (None, "", "null"):
        return None
    return int(value)


def _latest_scan_id(cur, target_pk: int) -> Optional[int]:
    """Latest scan for a monitored system (scan.target_id stores the text target_id)."""
    cur.execute(
        """
        SELECT MAX(s.scan_id) AS scan_id
        FROM monitored_targets t
        JOIN scan s ON s.target_id = t.target_id
        WHERE t.target_pk = %s
        """,
        (target_pk,),
    )
    row = cur.fetchone()
    return row["scan_id"] if row else None


def register_dependency_routes(app: Flask) -> None:

    # ---------- packages of one system (for the package dropdowns) ----------
    @app.route("/api/dependencies/packages/<int:target_pk>", methods=["GET"])
    def dependency_packages(target_pk: int):
        conn = _connect()
        try:
            with conn.cursor() as cur:
                scan_id = _latest_scan_id(cur, target_pk)
                if scan_id is None:
                    return jsonify({"rows": [], "scan_id": None})

                # Only vulnerable packages are stored per scan, so this lists the
                # packages with known vulnerabilities in the system's latest scan.
                cur.execute(
                    """
                    SELECT p.package_id, p.package_name, p.version,
                           COUNT(DISTINCT o.vulnerability_id) AS vuln_count
                    FROM package_vuln_observation o
                    JOIN packages_name p ON p.package_id = o.package_id
                    WHERE o.scan_id = %s
                    GROUP BY p.package_id, p.package_name, p.version
                    ORDER BY p.package_name, p.version
                    """,
                    (scan_id,),
                )
                return jsonify({"rows": cur.fetchall(), "scan_id": scan_id})
        finally:
            conn.close()

    # ---------- list recorded dependencies ----------
    @app.route("/api/dependencies", methods=["GET"])
    def list_dependencies():
        conn = _connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT d.dependency_id,
                           d.source_target_pk, st.target_id AS source_system,
                           d.source_package_id, sp.package_name AS source_package,
                           sp.version AS source_version,
                           d.dest_target_pk, dt.target_id AS dest_system,
                           d.dest_package_id, dp.package_name AS dest_package,
                           dp.version AS dest_version,
                           d.data_type, d.description, d.created_at
                    FROM data_dependency d
                    JOIN monitored_targets st ON st.target_pk = d.source_target_pk
                    JOIN monitored_targets dt ON dt.target_pk = d.dest_target_pk
                    LEFT JOIN packages_name sp ON sp.package_id = d.source_package_id
                    LEFT JOIN packages_name dp ON dp.package_id = d.dest_package_id
                    ORDER BY d.dependency_id DESC
                    """
                )
                return jsonify({"rows": cur.fetchall()})
        finally:
            conn.close()

    # ---------- add a dependency ----------
    @app.route("/api/dependencies", methods=["POST"])
    def add_dependency():
        payload = request.get_json(silent=True) or {}
        try:
            source_target_pk = _optional_int(payload.get("source_target_pk"))
            dest_target_pk = _optional_int(payload.get("dest_target_pk"))
            source_package_id = _optional_int(payload.get("source_package_id"))
            dest_package_id = _optional_int(payload.get("dest_package_id"))
        except (TypeError, ValueError):
            return jsonify({"error": "System and package IDs must be numbers."}), 400

        data_type = str(payload.get("data_type") or "").strip()
        description = str(payload.get("description") or "").strip() or None

        if source_target_pk is None or dest_target_pk is None:
            return jsonify({"error": "Choose both the sending and the receiving system."}), 400
        if source_target_pk == dest_target_pk:
            return jsonify({"error": "Sending and receiving systems must be different."}), 400
        data_type = data_type or None
        if data_type and len(data_type) > MAX_DATA_TYPE_LEN:
            return jsonify({"error": f"Data type must be {MAX_DATA_TYPE_LEN} characters or fewer."}), 400
        if description and len(description) > MAX_DESCRIPTION_LEN:
            return jsonify({"error": f"Description must be {MAX_DESCRIPTION_LEN} characters or fewer."}), 400

        conn = _connect()
        try:
            with conn.cursor() as cur:
                # <=> is MySQL's NULL-safe equals, so "whole system" rows compare correctly
                cur.execute(
                    """
                    SELECT dependency_id FROM data_dependency
                    WHERE source_target_pk = %s AND dest_target_pk = %s
                      AND source_package_id <=> %s AND dest_package_id <=> %s
                      AND data_type <=> %s
                    """,
                    (source_target_pk, dest_target_pk, source_package_id, dest_package_id, data_type),
                )
                if cur.fetchone():
                    return jsonify({"error": "This dependency is already recorded."}), 400

                cur.execute(
                    """
                    INSERT INTO data_dependency
                    (source_target_pk, source_package_id, dest_target_pk, dest_package_id,
                     data_type, description)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (source_target_pk, source_package_id, dest_target_pk, dest_package_id,
                     data_type, description),
                )
                conn.commit()
                return jsonify({"message": "Dependency saved.", "dependency_id": cur.lastrowid})
        except pymysql.err.IntegrityError:
            conn.rollback()
            return jsonify({"error": "A selected system or package no longer exists."}), 400
        finally:
            conn.close()

    # ---------- set everything one repository gets data from ----------
    @app.route("/api/dependencies/sources/<int:target_pk>", methods=["PUT"])
    def set_sources(target_pk: int):
        """
        Replaces the list of repositories that target_pk gets data from.
        Body: {"source_target_pks": [12, 15, 40]}
        Sources no longer in the list are removed, new ones are added,
        and ones already recorded are left as they are.
        """
        payload = request.get_json(silent=True) or {}
        raw = payload.get("source_target_pks")
        if not isinstance(raw, list):
            return jsonify({"error": "source_target_pks must be a list of repository IDs."}), 400
        try:
            wanted = {int(v) for v in raw}
        except (TypeError, ValueError):
            return jsonify({"error": "Repository IDs must be numbers."}), 400
        if target_pk in wanted:
            return jsonify({"error": "A repository can't get data from itself."}), 400

        conn = _connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT target_pk FROM monitored_targets WHERE target_pk = %s", (target_pk,))
                if not cur.fetchone():
                    return jsonify({"error": "Repository not found."}), 404

                cur.execute(
                    "SELECT dependency_id, source_target_pk FROM data_dependency WHERE dest_target_pk = %s",
                    (target_pk,),
                )
                existing_rows = cur.fetchall()
                existing = {r["source_target_pk"] for r in existing_rows}

                to_remove = [r["dependency_id"] for r in existing_rows if r["source_target_pk"] not in wanted]
                to_add = sorted(wanted - existing)

                if to_remove:
                    placeholders = ", ".join(["%s"] * len(to_remove))
                    cur.execute(f"DELETE FROM data_dependency WHERE dependency_id IN ({placeholders})", to_remove)
                if to_add:
                    cur.executemany(
                        "INSERT INTO data_dependency (source_target_pk, dest_target_pk) VALUES (%s, %s)",
                        [(src, target_pk) for src in to_add],
                    )
                conn.commit()
                return jsonify({
                    "message": "Sources saved.",
                    "added": len(to_add),
                    "removed": len(to_remove),
                    "total": len(wanted),
                })
        except pymysql.err.IntegrityError:
            conn.rollback()
            return jsonify({"error": "One of the selected repositories no longer exists. Refresh and try again."}), 400
        finally:
            conn.close()

    # ---------- delete a dependency ----------
    @app.route("/api/dependencies/<int:dependency_id>", methods=["DELETE"])
    def delete_dependency(dependency_id: int):
        conn = _connect()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM data_dependency WHERE dependency_id = %s", (dependency_id,))
                conn.commit()
                if cur.rowcount == 0:
                    return jsonify({"error": "Dependency not found."}), 404
                return jsonify({"message": "Dependency deleted."})
        finally:
            conn.close()

    # ---------- trace the downstream chain ----------
    @app.route("/api/dependencies/trace/<int:target_pk>", methods=["GET"])
    def trace_dependencies(target_pk: int):
        """
        Follows data flows downstream from one system, hop by hop (breadth-first).
        Optional ?package_id=N limits the first hop to flows from that package
        (or flows recorded for the whole system).
        """
        try:
            start_package_id = _optional_int(request.args.get("package_id"))
        except ValueError:
            return jsonify({"error": "package_id must be a number."}), 400

        conn = _connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT target_pk, target_id FROM monitored_targets WHERE target_pk = %s",
                    (target_pk,),
                )
                start = cur.fetchone()
                if not start:
                    return jsonify({"error": "System not found."}), 404

                # Vulnerabilities in the starting system's latest scan
                # (the "vulnerable packages from SBOM" flow in the data flow diagram)
                scan_id = _latest_scan_id(cur, target_pk)
                severity_counts: Dict[str, int] = {}
                vulnerable_packages = 0
                if scan_id is not None:
                    cur.execute(
                        """
                        SELECT COALESCE(v.severity, 'Unknown') AS severity,
                               COUNT(DISTINCT o.vulnerability_id) AS cnt
                        FROM package_vuln_observation o
                        JOIN vulnerability v ON v.vulnerability_id = o.vulnerability_id
                        WHERE o.scan_id = %s
                        GROUP BY COALESCE(v.severity, 'Unknown')
                        """,
                        (scan_id,),
                    )
                    severity_counts = {r["severity"]: r["cnt"] for r in cur.fetchall()}
                    cur.execute(
                        "SELECT COUNT(DISTINCT package_id) AS cnt FROM package_vuln_observation WHERE scan_id = %s",
                        (scan_id,),
                    )
                    vulnerable_packages = cur.fetchone()["cnt"]

                cur.execute(
                    """
                    SELECT d.dependency_id, d.source_target_pk, st.target_id AS source_system,
                           d.source_package_id, sp.package_name AS source_package,
                           d.dest_target_pk, dt.target_id AS dest_system,
                           d.dest_package_id, dp.package_name AS dest_package,
                           d.data_type
                    FROM data_dependency d
                    JOIN monitored_targets st ON st.target_pk = d.source_target_pk
                    JOIN monitored_targets dt ON dt.target_pk = d.dest_target_pk
                    LEFT JOIN packages_name sp ON sp.package_id = d.source_package_id
                    LEFT JOIN packages_name dp ON dp.package_id = d.dest_package_id
                    """
                )
                edges = cur.fetchall()
        finally:
            conn.close()

        outgoing: Dict[int, List[dict]] = {}
        for edge in edges:
            outgoing.setdefault(edge["source_target_pk"], []).append(edge)

        hops: List[dict] = []
        reached: Dict[int, dict] = {}
        visited = {target_pk}
        queue = deque([(target_pk, 0)])

        while queue:
            node, depth = queue.popleft()
            if depth >= MAX_TRACE_HOPS:
                continue
            for edge in outgoing.get(node, []):
                if depth == 0 and start_package_id is not None:
                    if edge["source_package_id"] not in (None, start_package_id):
                        continue
                hops.append({**edge, "hop": depth + 1})
                dest = edge["dest_target_pk"]
                if dest not in visited:
                    visited.add(dest)
                    reached[dest] = {"target_pk": dest, "target_id": edge["dest_system"], "hop": depth + 1}
                    queue.append((dest, depth + 1))

        return jsonify({
            "start": {
                "target_pk": start["target_pk"],
                "target_id": start["target_id"],
                "package_id": start_package_id,
                "latest_scan_id": scan_id,
                "vulnerable_packages": vulnerable_packages,
                "severity_counts": severity_counts,
            },
            "hops": hops,
            "affected_systems": sorted(reached.values(), key=lambda r: (r["hop"], r["target_id"])),
        })
