import sys
import shutil
from pathlib import Path
import pymysql

REPO_ROOT = Path(__file__).resolve().parent
SBOM_PATH = REPO_ROOT / "sbom-tools"

if str(SBOM_PATH) not in sys.path:
    sys.path.insert(0, str(SBOM_PATH))

from tejasai_db_config import DB_CONFIG
from sbom import Config, SBOMScanner

def get_conn():
    return pymysql.connect(**DB_CONFIG)

def get_linux_binary_targets():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT target_id
                FROM monitored_targets
                WHERE active = 1
                AND target_type = 'linux_binary'
                ORDER BY target_pk
            """)
            return [r["target_id"] for r in cur.fetchall()]
    finally:
        conn.close()

def update_last_scan_time(target_id):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE monitored_targets
                SET last_scan_time = NOW()
                WHERE target_id = %s
            """, (target_id,))
        conn.commit()
    finally:
        conn.close()

def get_latest_scan_id_for_path(path_value):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT scan_id
                FROM scan
                WHERE target_id = %s
                ORDER BY scan_id DESC
                LIMIT 1
            """, (path_value,))
            row = cur.fetchone()
            return row["scan_id"] if row else None
    finally:
        conn.close()

def rename_scan_target(scan_id, logical_name):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE scan
                SET target_id = %s
                WHERE scan_id = %s
            """, (logical_name, scan_id))
        conn.commit()
    finally:
        conn.close()

def main():
    Config.init_directories()
    scanner = SBOMScanner(use_cache=False, shallow_clone=True, skip_vuln=False)

    targets = get_linux_binary_targets()
    print(f"[SCAN] Found {len(targets)} linux_binary target(s)")

    for app in targets:
        binary_path = shutil.which(app)

        if not binary_path:
            print(f"[SCAN ERROR] {app} -> not found on system PATH")
            continue

        try:
            print(f"\n[SCAN] Scanning {app} at {binary_path}")
            scanner.scan(binary_path)

            latest_scan_id = get_latest_scan_id_for_path(binary_path)
            if latest_scan_id:
                rename_scan_target(latest_scan_id, app)

            update_last_scan_time(app)
            print(f"[SCAN] Completed: {app}")

        except Exception as e:
            print(f"[SCAN ERROR] {app} -> {e}")

if __name__ == "__main__":
    main()
