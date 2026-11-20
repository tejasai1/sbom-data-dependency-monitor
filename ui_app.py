from __future__ import annotations

import csv
import io
import json
import os
import sys
import threading
import time
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

from flask import Flask, jsonify, render_template, request, send_from_directory

# ---------------- PATH SETUP FIRST ----------------
REPO_ROOT = Path(__file__).resolve().parent
SBOM_MODULE_PATH = REPO_ROOT / "sbom-tools"

if str(SBOM_MODULE_PATH) not in sys.path:
    sys.path.insert(0, str(SBOM_MODULE_PATH))
# --------------------------------------------------

from db_monitor_job import monitor_once
from dependency_routes import register_dependency_routes
from impact_routes import register_impact_routes
from discovery_routes import register_discovery_routes
from settings_routes import (
    register_settings_routes,
    auto_scan_is_due,
    mark_auto_scan_started,
    mark_auto_scan_finished,
    get_auto_scan_interval_minutes,
    describe_interval,
    set_auto_scan_total,
    set_auto_scan_current_target,
    mark_auto_scan_target_done,
)

_config = None
_scanner_class = None


def get_config():
    global _config
    if _config is None:
        from sbom import Config  # type: ignore
        _config = Config
    return _config


def get_scanner_class():
    global _scanner_class
    if _scanner_class is None:
        from sbom import SBOMScanner  # type: ignore
        if not hasattr(SBOMScanner, "get_report"):
            raise RuntimeError(
                "SBOMScanner class is missing 'get_report' method. Please check sbom.py file."
            )
        _scanner_class = SBOMScanner
    return _scanner_class


@dataclass
class TreeNode:
    name: str
    children: List["TreeNode"]


def build_dependency_tree(graph: List[Dict[str, str]]) -> List[Dict[str, object]]:
    children_map: Dict[str, List[str]] = {}
    child_counts: Dict[str, int] = {}

    for edge in graph:
        parent = edge.get("parent")
        child = edge.get("child")
        if not parent or not child:
            continue

        children_map.setdefault(parent, []).append(child)
        child_counts[child] = child_counts.get(child, 0) + 1
        child_counts.setdefault(parent, child_counts.get(parent, 0))

    all_nodes = set(children_map.keys()) | set(child_counts.keys())
    roots = [node for node in all_nodes if child_counts.get(node, 0) == 0]
    if not roots and all_nodes:
        roots = sorted(all_nodes)

    expanded: Set[str] = set()

    def build_node(name: str) -> TreeNode:
        # Expand each package only once. If it appears again elsewhere in the
        # tree, show it without its children (like "deduped" in npm ls).
        # This keeps the tree the same size as the graph instead of copying
        # shared sub-trees for every path that reaches them.
        if name in expanded:
            return TreeNode(name=name, children=[])
        expanded.add(name)

        children = [
            build_node(child)
            for child in sorted(children_map.get(name, []))
        ]
        return TreeNode(name=name, children=children)

    tree = [build_node(root) for root in sorted(roots)]
    return [
        {"name": node.name, "children": _serialize_child_nodes(node.children)}
        for node in tree
    ]


def _serialize_child_nodes(children: List[TreeNode]) -> List[Dict[str, object]]:
    serialized: List[Dict[str, object]] = []
    for child in children:
        serialized.append(
            {"name": child.name, "children": _serialize_child_nodes(child.children)}
        )
    return serialized


def normalize_active(value) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if value is None:
        return 1

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "active"}:
        return 1
    if text in {"0", "false", "no", "n", "inactive"}:
        return 0
    return 1


def clean_target_row(row: Dict[str, object]) -> Dict[str, object]:
    return {
        "target_id": str(row.get("target_id", "")).strip(),
        "target_type": str(row.get("target_type", "")).strip(),
        "source_name": str(row.get("source_name", "")).strip(),
        "notes": str(row.get("notes", "")).strip(),
        "active": normalize_active(row.get("active", 1)),
    }


def validate_target_row(row: Dict[str, object]) -> str | None:
    if not row["target_id"]:
        return "Target ID is required"
    if not row["target_type"]:
        return "Target Type is required"
    if not row["source_name"]:
        return "Source Name is required"
    return None


def parse_csv_targets(raw_text: str) -> List[Dict[str, object]]:
    reader = csv.DictReader(io.StringIO(raw_text))
    rows: List[Dict[str, object]] = []
    for item in reader:
        rows.append(clean_target_row(item))
    return rows


def parse_json_targets(raw_text: str) -> List[Dict[str, object]]:
    parsed = json.loads(raw_text)

    if isinstance(parsed, list):
        source_rows = parsed
    elif isinstance(parsed, dict) and isinstance(parsed.get("rows"), list):
        source_rows = parsed["rows"]
    else:
        raise ValueError("JSON must be an array of target objects or an object containing a 'rows' array")

    rows: List[Dict[str, object]] = []
    for item in source_rows:
        if not isinstance(item, dict):
            raise ValueError("Each JSON row must be an object")
        rows.append(clean_target_row(item))

    return rows


def open_browser_window(url: str = "http://127.0.0.1:5050") -> None:
    try:
        time.sleep(2)

        if os.name == "nt":
            try:
                os.startfile(url)  # type: ignore[attr-defined]
                return
            except Exception as e:
                print(f"[BROWSER] os.startfile failed: {e}")

        try:
            import webbrowser
            opened = webbrowser.open_new(url)
            if not opened:
                print("[BROWSER] webbrowser.open_new returned False")
        except Exception as e:
            print(f"[BROWSER] webbrowser fallback failed: {e}")

    except Exception as e:
        print(f"[BROWSER] Could not open browser automatically: {e}")


def start_browser_thread() -> None:
    try:
        threading.Thread(target=open_browser_window, daemon=True).start()
    except Exception as e:
        print(f"[BROWSER] Failed to start browser thread: {e}")


def refresh_analytics_assets() -> None:
    refresh_script = REPO_ROOT / "refresh_dashboard_assets.py"
    try:
        print("[ANALYTICS] Refresh started...")
        subprocess.run(
            [sys.executable, str(refresh_script)],
            cwd=str(REPO_ROOT),
            check=True
        )
        print("[ANALYTICS] Refresh completed successfully.")
    except Exception as exc:
        print(f"[ANALYTICS] Refresh failed: {exc}")


def start_refresh_analytics_thread() -> None:
    try:
        threading.Thread(target=refresh_analytics_assets, daemon=True).start()
    except Exception as exc:
        print(f"[ANALYTICS] Failed to start refresh thread: {exc}")


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="ui/templates",
        static_folder="ui/static",
    )

    app.config["scanner_lock"] = threading.Lock()

    @app.after_request
    def add_no_cache_headers(response):
        if response.content_type and ("javascript" in response.content_type or "html" in response.content_type):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    def run_scan_core(target: str, use_cache: bool = True, shallow_clone: bool = True) -> Tuple[str, Dict[str, object]]:
        Config = get_config()
        SBOMScanner = get_scanner_class()
        Config.init_directories()

        lock: threading.Lock = app.config["scanner_lock"]

        with lock:
            scanner = SBOMScanner(
                use_cache=use_cache,
                shallow_clone=shallow_clone,
                skip_vuln=False,
            )
            scan_id = scanner.scan(target)
            report = scanner.get_report(scan_id) if scan_id else None

        if not scan_id:
            raise RuntimeError("Scan failed - no scan ID returned")

        if not report:
            raise RuntimeError("Report not found after scan")

        dependency_tree = build_dependency_tree(report.get("dependency_graph", []))
        report["dependency_tree"] = dependency_tree

        if "database_message" not in report:
            report["database_message"] = ""

        return scan_id, report

    def get_active_targets():
        import pymysql
        from tejasai_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_pk, target_id, target_type, source_name, active, notes, last_scan_time
                    FROM monitored_targets
                    WHERE active = 1
                    ORDER BY target_pk
                    """
                )
                return cur.fetchall()
        finally:
            conn.close()

    def update_last_scan_time(target_pk: int):
        import pymysql
        from tejasai_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE monitored_targets
                    SET last_scan_time = NOW()
                    WHERE target_pk = %s
                    """,
                    (target_pk,),
                )
                conn.commit()
        finally:
            conn.close()

    def background_scan_active_targets():
        targets = get_active_targets()
        if not targets:
            print("[AUTO-SCAN] No active targets found.")
            return

        print(f"[AUTO-SCAN] Found {len(targets)} active target(s).")
        set_auto_scan_total(len(targets))

        for row in targets:
            target_pk = row.get("target_pk")
            target_id = row.get("target_id", "")

            if not target_id:
                print(f"[AUTO-SCAN] Skipping empty target_id for target_pk={target_pk}")
                mark_auto_scan_target_done("skipped")
                continue

            set_auto_scan_current_target(target_id)
            try:
                print(f"[AUTO-SCAN] Scanning: {target_id}")
                scan_id, report = run_scan_core(
                    target=target_id,
                    use_cache=True,
                    shallow_clone=True,
                )
                update_last_scan_time(target_pk)
                print(f"[AUTO-SCAN] Success: {target_id} -> scan_id={scan_id}")
                mark_auto_scan_target_done("succeeded")

                try:
                    monitor_once(only_target=target_id)
                except Exception as mon_exc:
                    print(f"[AUTO-SCAN] monitor refresh failed after {target_id}: {mon_exc}")

            except Exception as exc:
                print(f"[AUTO-SCAN] Failed: {target_id} -> {exc}")
                mark_auto_scan_target_done("failed")

    @app.route("/")
    def index():
        reports_dir = str(REPO_ROOT / "reports")
        cache_buster = int(time.time())
        analytics_file = REPO_ROOT / "ui" / "static" / "dashboard_plus" / "dashboard_plus.html"
        analytics_ready = analytics_file.exists()

        return render_template(
            "index.html",
            reports_dir=reports_dir,
            default_target="",
            cache_buster=cache_buster,
            analytics_ready=analytics_ready,
        )

    @app.route("/api/analytics/refresh", methods=["POST"])
    def analytics_refresh():
        start_refresh_analytics_thread()
        return jsonify({"message": "Analytics refresh started in background."})

    @app.route("/api/db/targets", methods=["GET"])
    def get_targets():
        import pymysql
        from tejasai_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_pk, target_id, target_type, source_name, active, last_scan_time, notes
                    FROM monitored_targets
                    ORDER BY target_pk
                    """
                )
                rows = cur.fetchall()
            return jsonify({"rows": rows})
        finally:
            conn.close()

    @app.route("/api/db/targets", methods=["POST"])
    def add_target():
        import pymysql
        from tejasai_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        row = clean_target_row(payload)
        validation_error = validate_target_row(row)
        if validation_error:
            return jsonify({"error": validation_error}), 400

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*) AS count_value
                    FROM monitored_targets
                    WHERE target_id = %s
                    """,
                    (row["target_id"],),
                )
                existing = cur.fetchone()
                existing_count = existing.get("count_value", 0) if isinstance(existing, dict) else 0

                if existing_count > 0:
                    return jsonify({"error": "Target ID already exists"}), 400

                cur.execute(
                    """
                    INSERT INTO monitored_targets
                    (target_id, target_type, source_name, active, last_scan_time, notes)
                    VALUES (%s, %s, %s, %s, NULL, %s)
                    """,
                    (
                        row["target_id"],
                        row["target_type"],
                        row["source_name"],
                        row["active"],
                        row["notes"],
                    ),
                )
                conn.commit()

            return jsonify({"message": "Target added successfully"})
        finally:
            conn.close()

    @app.route("/api/db/targets/import", methods=["POST"])
    def import_targets():
        import pymysql
        from tejasai_db_config import DB_CONFIG

        content_type = request.form.get("content_type", "").strip().lower()
        raw_text = request.form.get("raw_text", "")

        uploaded_file = request.files.get("file")
        file_name = uploaded_file.filename if uploaded_file else ""

        try:
            if uploaded_file and file_name:
                ext = Path(file_name).suffix.lower()
                file_bytes = uploaded_file.read()
                raw_text = file_bytes.decode("utf-8-sig")

                if ext == ".csv":
                    content_type = "csv"
                elif ext == ".json":
                    content_type = "json"
                else:
                    return jsonify({"error": "Only CSV and JSON files are supported"}), 400
            else:
                if not raw_text.strip():
                    return jsonify({"error": "No import data provided"}), 400

            if content_type == "csv":
                rows = parse_csv_targets(raw_text)
            elif content_type == "json":
                rows = parse_json_targets(raw_text)
            else:
                return jsonify({"error": "Invalid content_type. Use csv or json"}), 400

        except UnicodeDecodeError:
            return jsonify({"error": "Could not decode uploaded file. Please use UTF-8 encoded CSV/JSON"}), 400
        except json.JSONDecodeError as exc:
            return jsonify({"error": f"Invalid JSON: {exc.msg}"}), 400
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": f"Import parsing failed: {exc}"}), 400

        if not rows:
            return jsonify({"error": "No valid rows found in import data"}), 400

        prepared_rows: List[Dict[str, object]] = []
        row_errors: List[str] = []

        for index, row in enumerate(rows, start=1):
            validation_error = validate_target_row(row)
            if validation_error:
                row_errors.append(f"Row {index}: {validation_error}")
            else:
                prepared_rows.append(row)

        if row_errors:
            return jsonify({"error": "Import validation failed", "details": row_errors}), 400

        conn = pymysql.connect(**DB_CONFIG)
        inserted_count = 0
        skipped_duplicates = 0
        duplicate_ids: List[str] = []

        try:
            with conn.cursor() as cur:
                for row in prepared_rows:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS count_value
                        FROM monitored_targets
                        WHERE target_id = %s
                        """,
                        (row["target_id"],),
                    )
                    existing = cur.fetchone()
                    existing_count = existing.get("count_value", 0) if isinstance(existing, dict) else 0

                    if existing_count > 0:
                        skipped_duplicates += 1
                        duplicate_ids.append(str(row["target_id"]))
                        continue

                    cur.execute(
                        """
                        INSERT INTO monitored_targets
                        (target_id, target_type, source_name, active, last_scan_time, notes)
                        VALUES (%s, %s, %s, %s, NULL, %s)
                        """,
                        (
                            row["target_id"],
                            row["target_type"],
                            row["source_name"],
                            row["active"],
                            row["notes"],
                        ),
                    )
                    inserted_count += 1

                conn.commit()

            return jsonify(
                {
                    "message": "Import completed",
                    "inserted": inserted_count,
                    "skipped_duplicates": skipped_duplicates,
                    "duplicate_ids": duplicate_ids,
                    "received": len(rows),
                }
            )
        finally:
            conn.close()

    @app.route("/api/db/targets/<int:target_pk>/status", methods=["PATCH"])
    def update_target_status(target_pk: int):
        import pymysql
        from tejasai_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        active = 1 if payload.get("active", False) else 0

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE monitored_targets
                    SET active = %s
                    WHERE target_pk = %s
                    """,
                    (active, target_pk),
                )
                conn.commit()

            return jsonify({"message": "Target status updated"})
        finally:
            conn.close()

    @app.route("/api/db/targets/<int:target_pk>", methods=["DELETE"])
    def delete_target(target_pk: int):
        import pymysql
        from tejasai_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    DELETE FROM monitored_targets
                    WHERE target_pk = %s
                    """,
                    (target_pk,),
                )
                conn.commit()

            return jsonify({"message": "Target deleted"})
        finally:
            conn.close()

    @app.route("/api/db/targets/<int:target_pk>/scan", methods=["POST"])
    def scan_target_from_db(target_pk: int):
        import pymysql
        from tejasai_db_config import DB_CONFIG

        payload = request.get_json(silent=True) or {}
        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT target_pk, target_id, target_type, source_name, active, notes
                    FROM monitored_targets
                    WHERE target_pk = %s
                    """,
                    (target_pk,),
                )
                row = cur.fetchone()

            if not row:
                return jsonify({"error": "Target not found"}), 404

            target = row.get("target_id", "")
            if not target:
                return jsonify({"error": "Target ID is empty"}), 400

            try:
                scan_id, report = run_scan_core(
                    target=target,
                    use_cache=use_cache,
                    shallow_clone=shallow_clone,
                )
            except (FileNotFoundError, ValueError, RuntimeError) as exc:
                error_msg = str(exc)
                print(f"[ERROR] DB target scan failed: {error_msg}", file=sys.stderr)
                return jsonify({"error": error_msg}), 400
            except Exception as exc:
                error_msg = str(exc)
                print(f"[ERROR] Unexpected DB target scan error: {error_msg}", file=sys.stderr)
                import traceback
                traceback.print_exc()
                return jsonify({"error": f"Scan failed: {error_msg}"}), 500

            update_last_scan_time(target_pk)

            try:
                monitor_once()
            except Exception as mon_exc:
                print(f"[ERROR] monitor refresh failed for {target}: {mon_exc}")

            start_refresh_analytics_thread()

            return jsonify(
                {
                    "message": "Target scanned successfully",
                    "target_pk": target_pk,
                    "target_id": target,
                    "scanId": scan_id,
                    "report": report,
                }
            )
        finally:
            conn.close()

    @app.route("/api/db/targets/scan-all-active", methods=["POST"])
    def scan_all_active_targets():
        payload = request.get_json(silent=True) or {}
        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)
        limit = payload.get("limit")

        rows = get_active_targets()

        if limit is not None:
            try:
                limit_value = int(limit)
                if limit_value > 0:
                    rows = rows[:limit_value]
            except Exception:
                pass

        if not rows:
            return jsonify({"error": "No active targets found"}), 400

        results = []
        success_count = 0
        failed_count = 0

        for row in rows:
            target_pk = row.get("target_pk")
            target_id = row.get("target_id", "")

            try:
                scan_id, report = run_scan_core(
                    target=target_id,
                    use_cache=use_cache,
                    shallow_clone=shallow_clone,
                )
                update_last_scan_time(target_pk)

                try:
                    monitor_once()
                except Exception as mon_exc:
                    print(f"[SCAN-ALL] monitor refresh failed for {target_id}: {mon_exc}")

                success_count += 1
                results.append(
                    {
                        "target_pk": target_pk,
                        "target_id": target_id,
                        "status": "success",
                        "scanId": scan_id,
                        "summary": report.get("summary", {}),
                    }
                )
            except Exception as exc:
                failed_count += 1
                results.append(
                    {
                        "target_pk": target_pk,
                        "target_id": target_id,
                        "status": "failed",
                        "error": str(exc),
                    }
                )

        start_refresh_analytics_thread()

        return jsonify(
            {
                "message": "Scan-all completed",
                "total": len(rows),
                "success_count": success_count,
                "failed_count": failed_count,
                "results": results,
            }
        )

    @app.route("/api/db/targets/scan-all-active/background", methods=["POST"])
    def scan_all_active_targets_background():
        def job():
            try:
                background_scan_active_targets()
            except Exception as exc:
                print(f"[AUTO-SCAN-BG] Background job failed: {exc}")

        threading.Thread(target=job, daemon=True).start()
        return jsonify({"message": "Background scan started"})

    @app.route("/api/db/latest-scans", methods=["GET"])
    def get_latest_scans():
        import pymysql
        from tejasai_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT scan_id, target_id, scan_time
                    FROM scan
                    ORDER BY scan_id DESC
                    LIMIT 50
                    """
                )
                rows = cur.fetchall()
            return jsonify({"rows": rows})
        finally:
            conn.close()

    @app.route("/api/scan", methods=["POST"])
    def scan():
        payload = request.get_json(silent=True) or {}
        target = payload.get("target")

        if not target:
            return jsonify({"error": "Target repository or path is required"}), 400

        use_cache = payload.get("useCache", True)
        shallow_clone = payload.get("shallowClone", True)

        try:
            scan_id, report = run_scan_core(
                target=target,
                use_cache=use_cache,
                shallow_clone=shallow_clone,
            )
        except (FileNotFoundError, ValueError, RuntimeError) as exc:
            error_msg = str(exc)
            print(f"[ERROR] Scan failed: {error_msg}", file=sys.stderr)
            return jsonify({"error": error_msg}), 400
        except Exception as exc:
            error_msg = str(exc)
            print(f"[ERROR] Unexpected error during scan: {error_msg}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"Scan failed: {error_msg}"}), 500

        start_refresh_analytics_thread()

        return jsonify({"scanId": scan_id, "report": report})

    @app.route("/api/reports", methods=["GET"])
    def list_reports():
        SBOMScanner = get_scanner_class()
        use_cache = request.args.get("useCache", "true").lower() != "false"
        shallow_clone = request.args.get("fullClone", "false").lower() != "true"
        scanner = SBOMScanner(use_cache=use_cache, shallow_clone=shallow_clone)
        reports = scanner.list_reports()
        return jsonify({"reports": reports})

    @app.route("/reports/<path:filename>", methods=["GET"])
    def download_report(filename: str):
        Config = get_config()
        return send_from_directory(Config.REPORTS_DIR, filename, as_attachment=True)

    @app.route("/api/db/monitor-log", methods=["GET"])
    def get_monitor_log():
        import pymysql
        from tejasai_db_config import DB_CONFIG

        conn = pymysql.connect(**DB_CONFIG)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT log_id, target_id, latest_scan_id, prev_scan_id, scan_time,
                           total_vulns, critical, high, medium, low, new_found, resolved
                    FROM monitor_log
                    ORDER BY log_id DESC
                    LIMIT 100
                    """
                )
                rows = cur.fetchall()
            return jsonify({"rows": rows})
        finally:
            conn.close()

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "message": "Server is running"}), 200

    register_dependency_routes(app)
    register_settings_routes(app)
    register_impact_routes(app)
    register_discovery_routes(app)

    if not app.config.get("auto_db_monitor_started"):
        app.config["auto_db_monitor_started"] = True

        def db_monitor_loop():
            # Checks once a minute whether a cycle is due, using the interval saved
            # in the Settings tab, so a changed setting applies within about a minute.
            while True:
                if auto_scan_is_due():
                    interval = describe_interval(get_auto_scan_interval_minutes())
                    mark_auto_scan_started()
                    try:
                        print(f"[AUTO-SCAN] cycle started (interval: every {interval})")
                        background_scan_active_targets()
                        print("[AUTO-SCAN] cycle completed")
                    except Exception as e:
                        print("[AUTO-SCAN ERROR]", e)
                    finally:
                        mark_auto_scan_finished()

                time.sleep(60)

        threading.Thread(target=db_monitor_loop, daemon=True).start()

    return app


def run_with_flask(application: Flask) -> None:
    print("=" * 60)
    print("Starting Flask development server...")
    print("=" * 60)
    print("SERVER IS RUNNING!")
    print("Open your browser and go to:")
    print("http://10.14.64.76:5050")
    print("=" * 60)
    print("WARNING: Using Flask development server")
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    start_browser_thread()
    application.run(debug=True, threaded=True, use_reloader=False, host="0.0.0.0", port=5050)


def run_with_waitress(application: Flask) -> None:
    from waitress import serve

    print("=" * 60)
    print("Starting server with Waitress...")
    print("=" * 60)
    print("SERVER IS RUNNING!")
    print("Open your browser and go to:")
    print("http://10.14.64.76:5050")
    print("=" * 60)
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    start_browser_thread()
    serve(application, host="0.0.0.0", port=5050, threads=16)


if __name__ == "__main__":
    application = create_app()

    try:
        import waitress  # noqa: F401
        run_with_waitress(application)
    except ImportError as e:
        print(f"Waitress not found: {e}")
        print("Falling back to Flask development server...")
        run_with_flask(application)
    except Exception as e:
        print(f"Error starting Waitress server: {e}")
        print("Falling back to Flask development server...")
        run_with_flask(application)