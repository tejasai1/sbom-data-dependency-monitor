import sys
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

def get_active_targets():
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT target_id, target_type
                FROM monitored_targets
                WHERE active = 1
                AND target_type IN ('github', 'path')
                ORDER BY target_pk
            """)
            return cur.fetchall()
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

def main():
    Config.init_directories()
    scanner = SBOMScanner(use_cache=True, shallow_clone=True, skip_vuln=False)

    targets = get_active_targets()
    print(f"[SCAN] Found {len(targets)} supported active target(s)")

    for row in targets:
        target = row["target_id"]
        try:
            print(f"\n[SCAN] Scanning: {target}")
            scan_id = scanner.scan(target)
            update_last_scan_time(target)
            print(f"[SCAN] Completed: {scan_id}")
        except Exception as e:
            print(f"[SCAN ERROR] {target} -> {e}")

if __name__ == "__main__":
    main()
