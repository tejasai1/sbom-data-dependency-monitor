#!/usr/bin/env python
# coding: utf-8

"""
Database storage module for SBOM reports
Automatically stores scan results to MySQL database
"""

import re
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

import pymysql
from tejasai_db_config import DB_CONFIG


DB_NAME = DB_CONFIG["database"]


class DatabaseStorage:
    """Handles automatic storage of SBOM reports to MySQL database"""

    def __init__(self):
        self.connection: Optional[pymysql.Connection] = None
        self.db_available = False

    def _connect(self) -> bool:
        """Connect to MySQL database - reuse existing connection if available"""
        if self.connection:
            try:
                self.connection.ping(reconnect=False)
                return True
            except Exception:
                try:
                    self.connection.close()
                except Exception:
                    pass
                self.connection = None

        try:
            print(f"  [db] Connecting to database: {DB_NAME} at {DB_CONFIG['host']}:{DB_CONFIG['port']}")
            self.connection = pymysql.connect(**DB_CONFIG)
            self._create_tables()
            self.db_available = True
            print("  [db] Connection successful!")
            return True
        except Exception as e:
            print(f"  [db] ERROR: Could not connect to database: {e}")
            print(f"  [db] Check: MySQL server running? Network accessible? Database '{DB_NAME}' exists?")
            print("  [db] Scan will continue, but results won't be stored in database")
            self.db_available = False
            return False

    def _sanitize_table_name(self, name: str) -> str:
        """Convert repository name/scan_id to a valid MySQL table name"""
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        sanitized = re.sub(r"_+", "_", sanitized)
        sanitized = sanitized.strip("_")
        sanitized = sanitized[:64]

        if sanitized and not sanitized[0].isalpha() and sanitized[0] != "_":
            sanitized = "_" + sanitized

        if not sanitized:
            sanitized = "scan_default"

        return sanitized

    def _create_tables(self):
        """Create required normalized tables if they do not exist"""
        if not self.connection:
            return

        with self.connection.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan (
                    scan_id INT AUTO_INCREMENT PRIMARY KEY,
                    target_id VARCHAR(512) NOT NULL,
                    scan_time DATETIME NOT NULL
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS packages_name (
                    package_id INT AUTO_INCREMENT PRIMARY KEY,
                    package_name VARCHAR(255) NOT NULL,
                    version VARCHAR(255) NOT NULL,
                    UNIQUE KEY uq_package_version (package_name, version)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability (
                    vulnerability_id INT AUTO_INCREMENT PRIMARY KEY,
                    cve_id VARCHAR(255) NOT NULL,
                    severity VARCHAR(50),
                    UNIQUE KEY uq_cve (cve_id)
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS package_vuln_observation (
                    observation_id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id INT NOT NULL,
                    package_id INT NOT NULL,
                    vulnerability_id INT NOT NULL,
                    detected_version VARCHAR(255),
                    fixed_version VARCHAR(255),
                    FOREIGN KEY (scan_id) REFERENCES scan(scan_id),
                    FOREIGN KEY (package_id) REFERENCES packages_name(package_id),
                    FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(vulnerability_id)
                )
            """)

        self.connection.commit()

    def _parse_ts(self, ts: Optional[str]) -> datetime:
        if not ts:
            return datetime.now()
        try:
            return datetime.fromisoformat(ts.replace("T", " ").split(".")[0])
        except Exception:
            return datetime.now()

    def save_report(self, report_data: Dict[str, Any]) -> Tuple[bool, Optional[int]]:
        """
        Save report into normalized schema.
        Returns: (success, scan_id)
        """
        if not self._connect():
            return False, None

        assert self.connection is not None

        target = str(report_data.get("target", "")).strip()
        ts = self._parse_ts(report_data.get("timestamp"))
        packages = report_data.get("packages", []) or []

        try:
            with self.connection.cursor() as cur:
                cur.execute(
                    "INSERT INTO scan (target_id, scan_time) VALUES (%s, %s)",
                    (target, ts),
                )
                scan_id = cur.lastrowid

                for pkg in packages:
                    pkg_name = str(pkg.get("package", "")).strip()
                    pkg_version = str(pkg.get("version", "")).strip()
                    vuln_id = str(pkg.get("vulnerability_id", "")).strip()
                    severity = str(pkg.get("severity", "")).strip() or None
                    fixed_version = str(pkg.get("fixed_version", "")).strip() or None

                    if not pkg_name or not pkg_version:
                        continue

                    cur.execute(
                        """
                        INSERT INTO packages_name (package_name, version)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE package_id = LAST_INSERT_ID(package_id)
                        """,
                        (pkg_name, pkg_version),
                    )
                    package_id = cur.lastrowid

                    if not vuln_id or vuln_id.lower() in {"none", "null", ""}:
                        continue

                    cur.execute(
                        """
                        INSERT INTO vulnerability (cve_id, severity)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE
                            severity = VALUES(severity),
                            vulnerability_id = LAST_INSERT_ID(vulnerability_id)
                        """,
                        (vuln_id, severity),
                    )
                    vulnerability_id = cur.lastrowid

                    cur.execute(
                        """
                        INSERT INTO package_vuln_observation
                        (scan_id, package_id, vulnerability_id, detected_version, fixed_version)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (scan_id, package_id, vulnerability_id, pkg_version, fixed_version),
                    )

            self.connection.commit()
            return True, scan_id

        except Exception as e:
            self.connection.rollback()
            print(f"  [db] ERROR saving report: {e}")
            return False, None

    def store_report(self, report_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Backward-compatible wrapper expected by sbom.py.
        Returns: (success, table_name)
        """
        success, scan_id = self.save_report(report_data)

        table_name = None
        if scan_id is not None:
            table_name = f"scan_{scan_id}"

        return success, table_name

    def close(self):
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None


_db_storage_instance = None


def get_db_storage():
    global _db_storage_instance
    if _db_storage_instance is None:
        _db_storage_instance = DatabaseStorage()
    return _db_storage_instance