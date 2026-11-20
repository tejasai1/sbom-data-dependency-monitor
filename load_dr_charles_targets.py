import pymysql
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "sbom-tools"))
from tejasai_db_config import DB_CONFIG

# Dr. Charles's application list from sossy.bash
APPS = ["mysql", "dockerd", "apt", "apache2", "nginx", "python3.12", "git"]

def main():
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM monitored_targets")
            for app in APPS:
                cur.execute("""
                    INSERT INTO monitored_targets
                    (target_id, target_type, source_name, active, notes)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    app,
                    "linux_binary",
                    "dr_charles_bash",
                    1,
                    "Imported from Dr. Charles sossy.bash APPS list"
                ))
        conn.commit()
        print(f"[OK] Loaded {len(APPS)} Dr. Charles targets into monitored_targets")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
