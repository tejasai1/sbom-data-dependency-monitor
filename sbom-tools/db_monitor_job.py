import pymysql
from tejasai_db_config import DB_CONFIG


def get_conn():
    return pymysql.connect(**DB_CONFIG)


def get_targets(conn):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT s.target_id
            FROM scan s
            JOIN monitored_targets mt ON s.target_id = mt.target_id
            WHERE mt.active = 1
            ORDER BY s.target_id;
        """)
        return [r["target_id"] for r in cur.fetchall()]


def last_two_scans(conn, target_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT scan_id, scan_time
            FROM scan
            WHERE target_id = %s
            ORDER BY scan_id DESC
            LIMIT 2
        """, (target_id,))
        return cur.fetchall()


def severity_counts(conn, scan_id):
    sql = """
    SELECT LOWER(COALESCE(v.severity, 'unknown')) AS sev, COUNT(DISTINCT o.package_id, o.vulnerability_id) AS c
    FROM package_vuln_observation o
    JOIN vulnerability v ON o.vulnerability_id = v.vulnerability_id
    WHERE o.scan_id = %s
    GROUP BY LOWER(COALESCE(v.severity, 'unknown'))
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total = 0

    with conn.cursor() as cur:
        cur.execute(sql, (scan_id,))
        for r in cur.fetchall():
            sev = r["sev"]
            c = int(r["c"])
            total += c
            if sev in counts:
                counts[sev] = c

    return total, counts


def vuln_set(conn, scan_id):
    sql = """
    SELECT pn.package_name, pn.version, v.cve_id
    FROM package_vuln_observation o
    JOIN packages_name pn ON o.package_id = pn.package_id
    JOIN vulnerability v ON o.vulnerability_id = v.vulnerability_id
    WHERE o.scan_id = %s
    """
    with conn.cursor() as cur:
        cur.execute(sql, (scan_id,))
        rows = cur.fetchall()

    return set((r["package_name"], r["version"], r["cve_id"]) for r in rows)


def already_logged(conn, target_id, latest_scan_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT 1
            FROM monitor_log
            WHERE target_id = %s AND latest_scan_id = %s
            LIMIT 1
        """, (target_id, latest_scan_id))
        return cur.fetchone() is not None


def insert_log(conn, row):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT IGNORE INTO monitor_log
            (
                target_id,
                latest_scan_id,
                prev_scan_id,
                scan_time,
                total_vulns,
                critical,
                high,
                medium,
                low,
                new_found,
                resolved,
                scan_id_latest,
                scan_id_prev
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            row["target_id"],
            row["latest_scan_id"],
            row["prev_scan_id"],
            row["scan_time"],
            row["total_vulns"],
            row["critical"],
            row["high"],
            row["medium"],
            row["low"],
            row["new_found"],
            row["resolved"],
            row["latest_scan_id"],
            row["prev_scan_id"]
        ))
    conn.commit()


def monitor_once(only_target=None):
    conn = get_conn()
    try:
        targets = [only_target] if only_target else get_targets(conn)
        if not targets:
            print("[MONITOR] No active scanned targets found.")
            return

        for t in targets:
            scans = last_two_scans(conn, t)
            if not scans:
                continue

            latest = scans[0]
            prev = scans[1] if len(scans) > 1 else None

            latest_id = int(latest["scan_id"])
            latest_time = latest["scan_time"]

            if already_logged(conn, t, latest_id):
                print(f"[MONITOR] skip {t} (already logged latest_scan_id={latest_id})")
                continue

            total, counts = severity_counts(conn, latest_id)

            prev_id = None
            new_found = 0
            resolved = 0

            if prev:
                prev_id = int(prev["scan_id"])
                latest_set = vuln_set(conn, latest_id)
                prev_set = vuln_set(conn, prev_id)
                new_found = len(latest_set - prev_set)
                resolved = len(prev_set - latest_set)

            row = {
                "target_id": t,
                "latest_scan_id": latest_id,
                "prev_scan_id": prev_id,
                "scan_time": latest_time,
                "total_vulns": total,
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "new_found": new_found,
                "resolved": resolved,
            }

            insert_log(conn, row)
            print(f"[MONITOR] Logged {t}: scan_id={latest_id} total={total} new={new_found} resolved={resolved}")

    finally:
        conn.close()


if __name__ == "__main__":
    monitor_once()