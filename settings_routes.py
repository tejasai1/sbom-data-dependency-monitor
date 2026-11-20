"""
Settings routes and helpers.

Stores app settings in the app_settings table (one row per setting).
The first setting is the auto-scan interval; more can be added later as new rows.

Registered from ui_app.py with:  register_settings_routes(app)
The auto-scan loop in ui_app.py uses auto_scan_is_due(), mark_auto_scan_started()
and mark_auto_scan_finished() instead of a fixed time.sleep(120), and
background_scan_active_targets() reports progress with set_auto_scan_total(),
set_auto_scan_current_target() and mark_auto_scan_target_done().
Needs the app_settings table (sql/create_app_settings.sql).
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

import pymysql
from flask import Flask, jsonify, request

from tejasai_db_config import DB_CONFIG

# ---------- auto-scan interval choices (stored in minutes) ----------
AUTO_SCAN_KEY = "auto_scan_interval_minutes"
LAST_SCAN_KEY = "auto_scan_last_completed_utc"

AUTO_SCAN_OPTIONS = [
    {"minutes": 5, "label": "5 minutes"},
    {"minutes": 1440, "label": "1 day"},
    {"minutes": 2880, "label": "2 days"},
    {"minutes": 7200, "label": "5 days"},
]
ALLOWED_MINUTES = {o["minutes"] for o in AUTO_SCAN_OPTIONS}
DEFAULT_INTERVAL_MINUTES = 5

# Whether a cycle is running right now. The loop runs in this same process,
# so memory is enough for this; it doesn't need to survive a restart.
_state_lock = threading.Lock()
_running_since: Optional[datetime] = None
_last_completed_fallback: Optional[datetime] = None  # used only if the database is unreachable

# Progress of the cycle that is running now, and a summary of the last finished one.
_progress = {"total": 0, "done": 0, "succeeded": 0, "failed": 0, "skipped": 0, "current": None}
_last_cycle: Optional[dict] = None


def _connect():
    return pymysql.connect(**DB_CONFIG)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def describe_interval(minutes: int) -> str:
    for option in AUTO_SCAN_OPTIONS:
        if option["minutes"] == minutes:
            return option["label"]
    return f"{minutes} minutes"


# ---------- reading and writing settings ----------
def get_setting(key: str) -> Optional[str]:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT setting_value FROM app_settings WHERE setting_key = %s", (key,))
            row = cur.fetchone()
            return row["setting_value"] if row else None
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
    conn = _connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO app_settings (setting_key, setting_value) VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
                """,
                (key, value),
            )
        conn.commit()
    finally:
        conn.close()


def get_auto_scan_interval_minutes() -> int:
    try:
        value = int(get_setting(AUTO_SCAN_KEY) or DEFAULT_INTERVAL_MINUTES)
    except Exception:
        return DEFAULT_INTERVAL_MINUTES
    return value if value in ALLOWED_MINUTES else DEFAULT_INTERVAL_MINUTES


def get_last_completed() -> Optional[datetime]:
    try:
        value = get_setting(LAST_SCAN_KEY)
        return datetime.fromisoformat(value) if value else None
    except Exception:
        return _last_completed_fallback


# ---------- used by the auto-scan loop in ui_app.py ----------
def auto_scan_is_due() -> bool:
    """True when no cycle has finished yet, or the saved interval has passed since the last one."""
    last = get_last_completed()
    if last is None:
        return True
    return _now() >= last + timedelta(minutes=get_auto_scan_interval_minutes())


def mark_auto_scan_started() -> None:
    global _running_since
    with _state_lock:
        _running_since = _now()
        _progress.update(total=0, done=0, succeeded=0, failed=0, skipped=0, current=None)


def mark_auto_scan_finished() -> None:
    global _running_since, _last_completed_fallback, _last_cycle
    finished = _now()
    with _state_lock:
        if _running_since is not None:
            _last_cycle = {
                "total": _progress["total"],
                "succeeded": _progress["succeeded"],
                "failed": _progress["failed"],
                "skipped": _progress["skipped"],
                "started": _running_since.isoformat(),
                "finished": finished.isoformat(),
            }
        _running_since = None
        _progress["current"] = None
        _last_completed_fallback = finished
    try:
        set_setting(LAST_SCAN_KEY, finished.isoformat())
    except Exception as e:
        print("[AUTO-SCAN] could not record finish time:", e)


# ---------- progress, reported by background_scan_active_targets() ----------
def set_auto_scan_total(total: int) -> None:
    """Called once the list of active targets is known."""
    with _state_lock:
        _progress.update(total=int(total), done=0, succeeded=0, failed=0, skipped=0, current=None)


def set_auto_scan_current_target(target_id: str) -> None:
    """Called just before a target is scanned."""
    with _state_lock:
        _progress["current"] = target_id


def mark_auto_scan_target_done(result: str) -> None:
    """Called after each target. result is "succeeded", "failed" or "skipped"."""
    with _state_lock:
        _progress["done"] += 1
        if result in ("succeeded", "failed", "skipped"):
            _progress[result] += 1


# ---------- routes ----------
def register_settings_routes(app: Flask) -> None:

    @app.route("/api/settings", methods=["GET"])
    def get_settings():
        interval = get_auto_scan_interval_minutes()
        last = get_last_completed()
        with _state_lock:
            running_since = _running_since
            progress = dict(_progress) if running_since is not None else None
            last_cycle = dict(_last_cycle) if _last_cycle else None

        next_due = (last + timedelta(minutes=interval)) if last else None
        return jsonify({
            "auto_scan": {
                "interval_minutes": interval,
                "interval_label": describe_interval(interval),
                "options": AUTO_SCAN_OPTIONS,
                "running": running_since is not None,
                "running_since": running_since.isoformat() if running_since else None,
                "last_completed": last.isoformat() if last else None,
                "next_due": next_due.isoformat() if next_due else None,
                "progress": progress,
                "last_cycle": last_cycle,
            }
        })

    @app.route("/api/settings/auto-scan", methods=["PUT"])
    def save_auto_scan_setting():
        payload = request.get_json(silent=True) or {}
        try:
            minutes = int(payload.get("interval_minutes"))
        except (TypeError, ValueError):
            return jsonify({"error": "Choose one of the listed intervals."}), 400
        if minutes not in ALLOWED_MINUTES:
            return jsonify({"error": "Choose one of the listed intervals."}), 400

        try:
            set_setting(AUTO_SCAN_KEY, str(minutes))
        except pymysql.MySQLError as e:
            return jsonify({"error": f"Could not save the setting: {e}"}), 500

        return jsonify({
            "message": f"Saved. Auto scan will run every {describe_interval(minutes)}.",
            "interval_minutes": minutes,
            "interval_label": describe_interval(minutes),
        })
