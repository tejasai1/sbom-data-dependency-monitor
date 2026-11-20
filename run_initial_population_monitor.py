#!/usr/bin/env python
# coding: utf-8

from __future__ import annotations

import sys
import time
from pathlib import Path

import pymysql

PROJECT_ROOT = Path(__file__).resolve().parent
SBOM_TOOLS_DIR = PROJECT_ROOT / "sbom-tools"

if str(SBOM_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(SBOM_TOOLS_DIR))

from tejasai_db_config import DB_CONFIG
from export_sergey_dataset import export_sergey_dataset
from sbom import Config, SBOMScanner
from db_monitor_job import monitor_once


BATCH_SIZE = 20
SLEEP_BETWEEN_REPOS = 3
SLEEP_BETWEEN_CYCLES = 120


def get_active_targets(limit: int = BATCH_SIZE):
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT target_id, source_name
                FROM monitored_targets
                WHERE active = 1
                  AND target_id LIKE 'https://github.com/%%'
                ORDER BY
                    CASE WHEN last_scan_time IS NULL THEN 0 ELSE 1 END,
                    last_scan_time ASC,
                    target_id ASC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()
    finally:
        conn.close()


def update_last_scan_time(target_id: str):
    conn = pymysql.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE monitored_targets
                SET last_scan_time = NOW()
                WHERE target_id = %s
                """,
                (target_id,),
            )
        conn.commit()
    finally:
        conn.close()


def run_one_cycle(scanner: SBOMScanner):
    targets = get_active_targets(BATCH_SIZE)

    if not targets:
        print("[MONITOR] No active GitHub targets found.")
        return

    print(f"[MONITOR] Starting cycle with {len(targets)} targets")

    for row in targets:
        target = row["target_id"]
        source_name = row.get("source_name", "")

        print("=" * 80)
        print(f"[MONITOR] Scanning: {target}")
        if source_name:
            print(f"[MONITOR] Source name: {source_name}")

        try:
            scanner.scan(target)
            update_last_scan_time(target)
            print(f"[MONITOR] Scan finished: {target}")
        except Exception as exc:
            print(f"[MONITOR] Scan failed for {target}: {exc}")

        time.sleep(SLEEP_BETWEEN_REPOS)

    try:
        monitor_once()
        print("[MONITOR] Monitor log updated")
    except Exception as exc:
        print(f"[MONITOR] Monitor refresh failed: {exc}")

    try:
        export_sergey_dataset()
        print("[MONITOR] Sergey Excel dataset updated")
    except Exception as exc:
        print(f"[MONITOR] Excel export failed: {exc}")


def main():
    Config.init_directories()

    scanner = SBOMScanner(
        use_cache=True,
        shallow_clone=True,
        skip_vuln=False,
    )

    print("[MONITOR] Initial population monitor started")
    print(f"[MONITOR] Batch size: {BATCH_SIZE}")
    print(f"[MONITOR] Sleep between repos: {SLEEP_BETWEEN_REPOS} seconds")
    print(f"[MONITOR] Sleep between cycles: {SLEEP_BETWEEN_CYCLES} seconds")

    while True:
        run_one_cycle(scanner)
        print(f"[MONITOR] Sleeping {SLEEP_BETWEEN_CYCLES} seconds before next cycle")
        time.sleep(SLEEP_BETWEEN_CYCLES)


if __name__ == "__main__":
    main()