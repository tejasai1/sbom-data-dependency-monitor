"""Stores data dependencies suggested by discovery until a manager approves or rejects them."""
import json

import pymysql

from .capstone_facts import DB_CONFIG, short_name
from .graph import CATEGORY_RANK

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS suggested_dependency (
  suggestion_id INT NOT NULL AUTO_INCREMENT,
  source_target_pk INT NOT NULL,
  dest_target_pk INT NOT NULL,
  found_in_target_pk INT NOT NULL,
  data VARCHAR(500) NOT NULL,
  items_json TEXT NOT NULL,
  category VARCHAR(30) NOT NULL,
  mechanism VARCHAR(30) NOT NULL,
  confidence VARCHAR(10) NOT NULL,
  reason VARCHAR(200) NOT NULL,
  evidence_json MEDIUMTEXT NOT NULL,
  model VARCHAR(100) NOT NULL,
  status VARCHAR(10) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TIMESTAMP NULL DEFAULT NULL,
  PRIMARY KEY (suggestion_id),
  KEY idx_sugg_pair (source_target_pk, dest_target_pk),
  KEY idx_sugg_status (status),
  CONSTRAINT fk_sugg_source FOREIGN KEY (source_target_pk)
    REFERENCES monitored_targets (target_pk) ON DELETE CASCADE,
  CONSTRAINT fk_sugg_dest FOREIGN KEY (dest_target_pk)
    REFERENCES monitored_targets (target_pk) ON DELETE CASCADE,
  CONSTRAINT fk_sugg_found FOREIGN KEY (found_in_target_pk)
    REFERENCES monitored_targets (target_pk) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""

_table_ready = False


def _connect():
    """Connect, creating the suggested_dependency table the first time if needed."""
    global _table_ready
    conn = pymysql.connect(**DB_CONFIG)
    if not _table_ready:
        with conn.cursor() as cur:
            cur.execute(CREATE_SQL)
        conn.commit()
        _table_ready = True
    return conn


def merge(suggestions):
    """Several flows can suggest the same 'A sends data to B'. Combine them into one
    suggestion, keeping every data item and every piece of evidence."""
    merged = {}
    for s in suggestions:
        key = (s["source_pk"], s["dest_pk"])
        m = merged.get(key)
        if m is None:
            merged[key] = {**s, "items": list(s["items"]), "evidence": list(s["evidence"]),
                           "data": [s["data"]], "reason": [s["reason"]]}
            continue
        m["items"] += [i for i in s["items"] if i not in m["items"]]
        m["evidence"] += [e for e in s["evidence"] if e not in m["evidence"]]
        if s["data"] not in m["data"]:
            m["data"].append(s["data"])
        if s["reason"] not in m["reason"]:
            m["reason"].append(s["reason"])
        if CATEGORY_RANK.get(s["category"], 0) > CATEGORY_RANK.get(m["category"], 0):
            m["category"] = s["category"]
    for m in merged.values():
        m["data"] = "; ".join(m["data"])[:500]
        m["reason"] = "; ".join(m["reason"])[:200]
    return list(merged.values())


def save(found_in_pk, model, suggestions):
    """Replace this target's pending suggestions with new ones.
    A link that is already recorded, or already suggested or decided, is skipped,
    so a rejected suggestion never comes back. Returns (added, skipped)."""
    conn = _connect()
    added, skipped = 0, []
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("DELETE FROM suggested_dependency "
                        "WHERE found_in_target_pk = %s AND status = 'pending'", (found_in_pk,))
            cur.execute("SELECT source_target_pk AS s, dest_target_pk AS d FROM data_dependency")
            recorded = {(r["s"], r["d"]) for r in cur.fetchall()}
            cur.execute("SELECT source_target_pk AS s, dest_target_pk AS d FROM suggested_dependency")
            known = {(r["s"], r["d"]) for r in cur.fetchall()}
            for s in merge(suggestions):
                pair = (s["source_pk"], s["dest_pk"])
                if pair in recorded:
                    skipped.append((s, "already recorded as a data dependency"))
                    continue
                if pair in known:
                    skipped.append((s, "already suggested or decided"))
                    continue
                cur.execute("""
                    INSERT INTO suggested_dependency
                    (source_target_pk, dest_target_pk, found_in_target_pk, data, items_json,
                     category, mechanism, confidence, reason, evidence_json, model)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (s["source_pk"], s["dest_pk"], found_in_pk, s["data"], json.dumps(s["items"]),
                     s["category"], s["mechanism"], s["confidence"], s["reason"],
                     json.dumps(s["evidence"]), model))
                known.add(pair)
                added += 1
        conn.commit()
    finally:
        conn.close()
    return added, skipped


def list_suggestions(status="pending"):
    """Suggestions with system names, newest first."""
    conn = _connect()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("""
                SELECT s.*, st.target_id AS source_id, dt.target_id AS dest_id,
                       ft.target_id AS found_in_id
                FROM suggested_dependency s
                JOIN monitored_targets st ON st.target_pk = s.source_target_pk
                JOIN monitored_targets dt ON dt.target_pk = s.dest_target_pk
                JOIN monitored_targets ft ON ft.target_pk = s.found_in_target_pk
                WHERE s.status = %s
                ORDER BY s.suggestion_id DESC""", (status,))
            rows = cur.fetchall()
    finally:
        conn.close()
    for r in rows:
        r["items"] = json.loads(r.pop("items_json"))
        r["evidence"] = json.loads(r.pop("evidence_json"))
    return rows


def decide(suggestion_id, approve):
    """Approve (record it as a real data dependency) or reject a pending suggestion.
    Returns the new status."""
    conn = _connect()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT * FROM suggested_dependency WHERE suggestion_id = %s FOR UPDATE",
                        (suggestion_id,))
            s = cur.fetchone()
            if not s:
                raise LookupError(f"Suggestion #{suggestion_id} not found.")
            if s["status"] != "pending":
                raise ValueError(f"Suggestion #{suggestion_id} was already {s['status']}.")
            if approve:
                cur.execute("""
                    SELECT dependency_id FROM data_dependency
                    WHERE source_target_pk = %s AND dest_target_pk = %s
                      AND source_package_id IS NULL AND dest_package_id IS NULL""",
                    (s["source_target_pk"], s["dest_target_pk"]))
                if not cur.fetchone():
                    items = ", ".join(json.loads(s["items_json"]))
                    description = (f"{s['data']}: {items}" if items else s["data"])[:500]
                    cur.execute("""
                        INSERT INTO data_dependency
                        (source_target_pk, dest_target_pk, data_type, description)
                        VALUES (%s, %s, %s, %s)""",
                        (s["source_target_pk"], s["dest_target_pk"], s["category"][:100], description))
            status = "approved" if approve else "rejected"
            cur.execute("UPDATE suggested_dependency SET status = %s, decided_at = CURRENT_TIMESTAMP "
                        "WHERE suggestion_id = %s", (status, suggestion_id))
        conn.commit()
        return status
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def approved_evidence():
    """The code evidence behind every approved link that is still recorded,
    so the trees can show the code that proves each data flow."""
    conn = _connect()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("""
                SELECT s.source_target_pk, s.dest_target_pk, s.data, s.items_json, s.category,
                       s.mechanism, s.confidence, s.reason, s.evidence_json, s.model, s.decided_at,
                       st.target_id AS source_id, dt.target_id AS dest_id,
                       ft.target_id AS found_in_id
                FROM suggested_dependency s
                JOIN monitored_targets st ON st.target_pk = s.source_target_pk
                JOIN monitored_targets dt ON dt.target_pk = s.dest_target_pk
                JOIN monitored_targets ft ON ft.target_pk = s.found_in_target_pk
                WHERE s.status = 'approved'
                  AND EXISTS (SELECT 1 FROM data_dependency d
                              WHERE d.source_target_pk = s.source_target_pk
                                AND d.dest_target_pk = s.dest_target_pk)""")
            rows = cur.fetchall()
    finally:
        conn.close()
    for r in rows:
        r["items"] = json.loads(r.pop("items_json"))
        r["evidence"] = json.loads(r.pop("evidence_json"))
        r["source"] = short_name(r["source_id"])
        r["destination"] = short_name(r["dest_id"])
        r["found_in"] = short_name(r["found_in_id"])
    return rows
if __name__ == "__main__":
    from .capstone_discovery import system_name
    rows = list_suggestions()
    print(f"Pending suggestions ({len(rows)}):")
    for r in rows:
        print(f"  #{r['suggestion_id']}  {system_name(r['source_id'])} sends data to "
              f"{system_name(r['dest_id'])}: {', '.join(r['items']) or r['data']}  "
              f"[found in {system_name(r['found_in_id'])}'s code, {len(r['evidence'])} evidence]")
