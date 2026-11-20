"""Saves impact reports, so an identical report is not generated (and paid for) twice."""
import copy
import hashlib
import json
import sys
from pathlib import Path

import pymysql

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sbom-tools"))
from tejasai_db_config import DB_CONFIG  # noqa: E402

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS impact_report (
  report_id INT NOT NULL AUTO_INCREMENT,
  target_pk INT NOT NULL,
  facts_hash CHAR(64) NOT NULL,
  model VARCHAR(100) NOT NULL,
  report_json MEDIUMTEXT NOT NULL,
  problems_json TEXT NOT NULL,
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (report_id),
  KEY idx_impact_lookup (target_pk, facts_hash, model),
  CONSTRAINT fk_impact_target FOREIGN KEY (target_pk)
    REFERENCES monitored_targets (target_pk) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

_table_ready = False


def _connect():
    """Connect, creating the impact_report table the first time if it doesn't exist."""
    global _table_ready
    conn = pymysql.connect(**DB_CONFIG)
    if not _table_ready:
        with conn.cursor() as cur:
            cur.execute(CREATE_SQL)
        conn.commit()
        _table_ready = True
    return conn


def facts_hash(facts):
    """Fingerprint of the facts. Scan numbers are left out, so a rescan with
    identical results still matches the saved report."""
    f = copy.deepcopy(facts)
    entries = [f["vulnerabilities"]] + [
        s["vulnerabilities"] for side in ("downstream", "upstream") for s in f[side]]
    for entry in entries:
        entry.pop("scan_id", None)
    text = json.dumps(f, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find(target_pk, fhash, model):
    """The newest saved report for exactly these facts and this model, or None."""
    conn = _connect()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("""
                SELECT report_json, problems_json, created_at FROM impact_report
                WHERE target_pk = %s AND facts_hash = %s AND model = %s
                ORDER BY report_id DESC LIMIT 1""", (target_pk, fhash, model))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {"report": json.loads(row["report_json"]),
            "problems": json.loads(row["problems_json"]),
            "created_at": row["created_at"]}


def save(target_pk, fhash, model, report, problems):
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO impact_report
                (target_pk, facts_hash, model, report_json, problems_json)
                VALUES (%s, %s, %s, %s, %s)""",
                (target_pk, fhash, model, json.dumps(report), json.dumps(problems)))
        conn.commit()
    finally:
        conn.close()