#!/usr/bin/env python
# coding: utf-8

"""
SBOM Scanner Tool - Generates SBOMs and scans for vulnerabilities
"""

import io
import sys

if sys.platform == "win32":
    if sys.stdout.encoding != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import argparse
import csv
import json
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    from .db_storage import get_db_storage
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from db_storage import get_db_storage


class Config:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent
    TOOLS_DIR = Path(__file__).resolve().parent
    BASE_DIR = PROJECT_ROOT
    REPORTS_DIR = BASE_DIR / "reports"
    TEMP_DIR = BASE_DIR / "temp"
    REPO_CACHE_DIR = Path(os.environ.get("SBOM_REPO_CACHE_DIR", r"C:\sbom-repo-cache"))

    SYFT_PATH = Path(
        os.environ.get("SYFT_PATH", TOOLS_DIR / "syft" / ("syft.exe" if os.name == "nt" else "syft"))
    )
    GRYPE_PATH = Path(
        os.environ.get("GRYPE_PATH", TOOLS_DIR / "grype" / ("grype.exe" if os.name == "nt" else "grype"))
    )

    @classmethod
    def init_directories(cls):
        cls.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        cls.TEMP_DIR.mkdir(parents=True, exist_ok=True)
        cls.REPO_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[ok] Directories initialized at {cls.BASE_DIR}")


def is_github_repo(url: str) -> bool:
    if not isinstance(url, str):
        return False

    u = urlparse(url.strip())
    if u.netloc not in {"github.com", "www.github.com"}:
        return False

    parts = [p for p in u.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return False

    excluded_paths = {
        "topics", "explore", "trending", "stars", "collections",
        "events", "sponsors", "marketplace", "pricing", "login",
        "signup", "settings", "notifications", "search", "about"
    }

    if parts[0] in excluded_paths:
        return False

    return True


def generate_safe_filename(target: str, is_github: bool) -> str:
    if is_github:
        parts = target.rstrip("/").split("/")
        github_parts = [p for p in parts if p and p not in ["http:", "https:", "github.com", "www.github.com"]]
        if len(github_parts) >= 2:
            owner = github_parts[-2]
            repo = github_parts[-1].replace(".git", "")
            filename = f"{owner}-{repo}"
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"scan-{timestamp}"
    else:
        path_obj = Path(target)
        if path_obj.exists():
            filename = path_obj.name if path_obj.is_dir() else path_obj.stem
        else:
            filename = target.replace("\\", "-").replace("/", "-").replace(":", "-")

    filename = re.sub(r'[<>:"/\\|?*]', "-", filename)
    filename = re.sub(r"\s+", "-", filename).strip(".-")
    return filename[:200] if len(filename) > 200 else filename or f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


def run_command(cmd: List[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout
    )


class SBOMScanner:
    def __init__(self, use_cache: bool = False, shallow_clone: bool = True, skip_vuln: bool = False):
        self.git_command = self._resolve_git_command()
        self.syft_path = Config.SYFT_PATH
        self.grype_path = Config.GRYPE_PATH
        self.use_cache = use_cache
        self.shallow_clone = shallow_clone
        self.skip_vuln = skip_vuln

        if not Path(self.syft_path).exists():
            raise FileNotFoundError(f"Syft not found at {self.syft_path}")
        if not self.skip_vuln and not Path(self.grype_path).exists():
            raise FileNotFoundError(f"Grype not found at {self.grype_path}")

    @staticmethod
    def _resolve_git_command() -> List[str]:
        git_path = shutil.which("git")
        if git_path:
            return [git_path]

        fallback_paths = [
            Path("C:/Program Files/Git/cmd/git.exe"),
            Path("C:/Program Files/Git/bin/git.exe"),
            Path("C:/Program Files (x86)/Git/cmd/git.exe"),
            Path("C:/Program Files (x86)/Git/bin/git.exe"),
        ]

        for path in fallback_paths:
            if path.exists():
                return [str(path)]

        raise FileNotFoundError("Git executable not found. Install Git or add it to PATH.")

    def _on_rm_error(self, func, path, exc_info):
        try:
            os.chmod(path, stat.S_IWRITE)
            func(path)
        except Exception:
            pass

    def _remove_repo_dir(self, repo_path: Path):
        if not repo_path.exists():
            return

        lock_file = repo_path / ".git" / "index.lock"
        if lock_file.exists():
            try:
                lock_file.unlink()
            except Exception:
                pass

        shutil.rmtree(repo_path, ignore_errors=False, onerror=self._on_rm_error)

    def _clone_repo(self, repo_url: str, destination: Path):
        if destination.exists():
            print(f"  -> Removing existing broken repo folder: {destination}")
            self._remove_repo_dir(destination)

        clone_cmd = [*self.git_command, "clone"]
        if self.shallow_clone:
            clone_cmd.extend(["--depth", "1", "--single-branch"])
        clone_cmd.extend([repo_url, str(destination)])

        print(f"  -> Cloning repository ({'shallow' if self.shallow_clone else 'full'} clone)...")

        max_retries = 2
        for attempt in range(max_retries + 1):
            result = run_command(clone_cmd, timeout=900)

            if result.returncode == 0:
                return

            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"

            if ("403" in error_msg or "forbidden" in error_msg.lower()) and attempt < max_retries:
                wait_time = (attempt + 1) * 10
                print(f"  -> GitHub rate limit detected. Waiting {wait_time} seconds before retry {attempt + 1}/{max_retries}...")
                time.sleep(wait_time)
                continue

            if "not found" in error_msg.lower() or "does not exist" in error_msg.lower():
                raise RuntimeError(f"Repository not found: {repo_url}. Please check that the repository exists and is accessible.")
            elif "403" in error_msg or "forbidden" in error_msg.lower():
                raise RuntimeError(
                    f"GitHub returned 403 Forbidden for {repo_url}.\n"
                    f"This usually means GitHub rate limiting (too many requests).\n"
                    f"Solutions:\n"
                    f"  - Wait 5-10 minutes and try again\n"
                    f"  - Enable 'Use cache' option if you've scanned this repo before\n"
                    f"  - Try a different repository\n"
                    f"Error details: {error_msg}"
                )
            elif "authentication" in error_msg.lower() or "permission" in error_msg.lower():
                raise RuntimeError(f"Authentication failed for {repo_url}. The repository may be private or require authentication.")
            else:
                raise RuntimeError(f"Failed to clone repository {repo_url}: {error_msg}")

    def _update_repo(self, repo_path: Path):
        print("  -> Updating cached repository...")

        lock_file = repo_path / ".git" / "index.lock"
        if lock_file.exists():
            try:
                lock_file.unlink()
            except OSError as exc:
                raise RuntimeError(f"Failed to remove stale git lock: {exc}") from exc

        if self.shallow_clone:
            commands = [
                [*self.git_command, "-C", str(repo_path), "fetch", "--depth", "1", "origin"],
                [*self.git_command, "-C", str(repo_path), "reset", "--hard", "FETCH_HEAD"],
                [*self.git_command, "-C", str(repo_path), "clean", "-fd"],
            ]
        else:
            commands = [
                [*self.git_command, "-C", str(repo_path), "pull", "--rebase"]
            ]

        for cmd in commands:
            result = run_command(cmd, timeout=300)
            if result.returncode == 0:
                continue

            stderr = result.stderr or ""
            stdout = result.stdout or ""
            error_msg = (stderr.strip() or stdout.strip() or "Unknown git update error")

            if "index.lock" in error_msg:
                lock_file = repo_path / ".git" / "index.lock"
                if lock_file.exists():
                    try:
                        lock_file.unlink()
                    except OSError as exc:
                        raise RuntimeError(f"Failed to remove git lock: {exc}") from exc

                    retry = run_command(cmd, timeout=300)
                    if retry.returncode == 0:
                        continue
                    error_msg = (retry.stderr or retry.stdout or error_msg).strip()

            raise RuntimeError(error_msg)

    def _clone_and_scan_github(self, owner: str, repo: str) -> Tuple[str, str, bool]:
        repo_url = f"https://github.com/{owner}/{repo}.git"

        if self.use_cache:
            cache_path = Config.REPO_CACHE_DIR / f"{owner}-{repo}"
            

            if cache_path.exists():
                try:
                    self._update_repo(cache_path)
                except RuntimeError as err:
                    print(f"  -> Cache update failed ({err}); removing broken cache and recloning...")
                    try:
                        self._remove_repo_dir(cache_path)
                    except Exception as cleanup_err:
                        raise RuntimeError(f"Failed to remove broken cache {cache_path}: {cleanup_err}") from cleanup_err
                    self._clone_repo(repo_url, cache_path)
            else:
                self._clone_repo(repo_url, cache_path)

            return str(cache_path), f"{owner}/{repo}", False

        temp_repo_path = Config.TEMP_DIR / f"{owner}-{repo}-{uuid.uuid4().hex[:8]}"
        self._clone_repo(repo_url, temp_repo_path)
        return str(temp_repo_path), f"{owner}/{repo}", True

    def scan(self, target: str) -> Optional[str]:
        cleanup_path: Optional[Path] = None
        is_github_target = is_github_repo(target)

        try:
            if is_github_target:
                parts = target.rstrip("/").split("/")
                github_parts = [p for p in parts if p and p not in ["http:", "https:", "github.com", "www.github.com"]]

                if len(github_parts) < 2:
                    raise ValueError(f"Invalid GitHub repository URL: {target}. Expected format: https://github.com/owner/repo")

                owner = github_parts[-2]
                repo = github_parts[-1].replace(".git", "")

                repo_path, scan_target, cleanup_needed = self._clone_and_scan_github(owner, repo)
                if cleanup_needed:
                    cleanup_path = Path(repo_path)
                print(f"  -> Scanning repository: {scan_target}")
            else:
                if "github.com" in target.lower():
                    raise ValueError(f"Invalid GitHub URL: {target}. This appears to be a GitHub page but not a repository. Use https://github.com/owner/repo")
                scan_target = target
                repo_path = scan_target

            filename = generate_safe_filename(target, is_github_target)
            scan_id = filename

            print(f"\n{'=' * 60}")
            print(f"Scanning: {target}")
            print(f"{'=' * 60}\n")

            total_start = time.time()

            print("[1/3] Generating SBOM...")
            print("      Please wait, scanning in progress...")
            sys.stdout.flush()
            step_start = time.time()
            sbom_data = self._generate_sbom(repo_path if is_github_target else scan_target)
            elapsed = time.time() - step_start
            print(f"      [OK] SBOM generation completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)\n")

            if self.skip_vuln:
                print("[2/3] Skipping vulnerability scan (--skip-vuln enabled)")
                vuln_data = {"matches": []}
            else:
                print("[2/3] Scanning vulnerabilities...")
                print("      Please wait, scanning in progress...")
                print("      This may take 10-30 minutes for large repositories...")
                sys.stdout.flush()
                step_start = time.time()
                vuln_data = self._scan_vulnerabilities(repo_path if is_github_target else scan_target)
                elapsed = time.time() - step_start
                print(f"      [OK] Vulnerability scan completed in {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)\n")

            print("[3/3] Creating reports...")
            step_start = time.time()
            report_data = self._create_report(scan_id, target, sbom_data, vuln_data)

            total_vulns = report_data.get("summary", {}).get("total_vulnerabilities", 0)
            if total_vulns > 0:
                print(f"      Found {total_vulns} vulnerabilities:")
                print(f"        - Critical: {report_data.get('summary', {}).get('critical', 0)}")
                print(f"        - High: {report_data.get('summary', {}).get('high', 0)}")
                print(f"        - Medium: {report_data.get('summary', {}).get('medium', 0)}")
                print(f"        - Low: {report_data.get('summary', {}).get('low', 0)}")
            else:
                print("      No vulnerabilities found - all packages are secure!")

            self._save_json_report(scan_id, report_data)
            self._save_csv_report(scan_id, report_data)
            elapsed = time.time() - step_start
            print(f"      [OK] Reports created in {elapsed:.1f} seconds\n")

            print("[4/4] Saving to database...")
            table_name = None
            database_message = ""
            try:
                db_storage = get_db_storage()
                print(f"      Attempting to save report '{scan_id}' to database...")
                success, table_name = db_storage.store_report(report_data)
                if success:
                    if table_name:
                        database_message = f"Report saved to database table: {table_name}"
                        print(f"      [OK] Report saved to database successfully! Table: {table_name}\n")
                        report_data["database_table"] = table_name
                        report_data["database_message"] = database_message
                    else:
                        database_message = "Report saved to database successfully"
                        print("      [OK] Report saved to database successfully!\n")
                        report_data["database_message"] = database_message
                else:
                    database_message = "Failed to save report to database (check server console for details)"
                    print("      [ERROR] Report NOT saved to database (check error messages above)\n")
                    report_data["database_message"] = database_message
            except Exception as e:
                database_message = f"Database error: {str(e)}"
                print(f"      [ERROR] Could not save to database: {e}")
                import traceback
                traceback.print_exc()
                print()
                report_data["database_message"] = database_message

            if len(report_data.get("dependency_graph", [])) > 1000:
                print(f"      [info] Large dependency graph ({len(report_data['dependency_graph'])} edges) - processing optimized\n")

            total_time = time.time() - total_start
            print(f"{'=' * 60}")
            print("Scan completed successfully!")
            print(f"Total time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
            print("Reports saved:")
            print(f"   - {Config.REPORTS_DIR / scan_id}.json")
            print(f"   - {Config.REPORTS_DIR / scan_id}.csv")
            if table_name:
                print(f"   - MySQL database ({table_name})")
            else:
                print("   - MySQL database (saved successfully)")
            print(f"{'=' * 60}\n")

            return scan_id

        except Exception as e:
            print(f"\nScan failed: {str(e)}\n")
            raise

        finally:
            if cleanup_path and cleanup_path.exists():
                try:
                    shutil.rmtree(cleanup_path, onerror=self._on_rm_error)
                    print("  -> Cleaned up temporary files")
                except Exception as e:
                    print(f"  !! Warning: Could not remove temp directory: {e}")

    def _generate_sbom(self, target: str) -> dict:
        target_path_obj = Path(target)
        if target_path_obj.exists():
            target_path = target_path_obj.resolve()
            syft_target = f"dir:{target_path}" if target_path.is_dir() else str(target_path)
        else:
            syft_target = target

        sys.stdout.write("      Running Syft (optimized)... ")
        sys.stdout.flush()

        result = run_command(
            [str(self.syft_path), syft_target, "-o", "json"],
            timeout=600
        )

        if result.returncode != 0:
            error_msg = (result.stderr or "").strip() or (result.stdout or "").strip() or "Unknown error"
            raise RuntimeError(f"SBOM generation failed: {error_msg}")

        if not result.stdout:
            raise RuntimeError(f"SBOM generation produced no output. stderr: {result.stderr or 'None'}")

        try:
            data = json.loads(result.stdout)
            sys.stdout.write("[OK]\n")
            sys.stdout.flush()
            return data
        except json.JSONDecodeError as e:
            output_preview = (result.stdout or "")[:500] if result.stdout else "No output"
            raise RuntimeError(f"Failed to parse SBOM JSON output: {e}\nOutput: {output_preview}")

    def _scan_vulnerabilities(self, target: str) -> dict:
        target_path_obj = Path(target)
        if target_path_obj.exists():
            target_path = target_path_obj.resolve()
            grype_target = f"dir:{target_path}" if target_path.is_dir() else str(target_path)
        else:
            grype_target = target

        sys.stdout.write("      Running Grype (optimized)... ")
        sys.stdout.flush()

        grype_cmd = [
            str(self.grype_path),
            grype_target,
            "-o", "json",
        ]

        result = run_command(grype_cmd, timeout=1200)

        if result.returncode not in [0, 1]:
            error_msg = (result.stderr or "").strip() or (result.stdout or "").strip() or "Unknown error"
            raise RuntimeError(f"Vulnerability scan failed: {error_msg}")

        if not result.stdout:
            raise RuntimeError(f"Vulnerability scan produced no output. stderr: {result.stderr or 'None'}")

        try:
            data = json.loads(result.stdout)
            sys.stdout.write("[OK]\n")
            sys.stdout.flush()
            return data
        except json.JSONDecodeError as e:
            output_preview = (result.stdout or "")[:500] if result.stdout else "No output"
            raise RuntimeError(f"Failed to parse vulnerability JSON output: {e}\nOutput: {output_preview}")

    def _create_report(self, scan_id: str, target: str, sbom_data: dict, vuln_data: dict) -> dict:
        packages = sbom_data.get("artifacts", [])
        vulnerabilities = vuln_data.get("matches", [])

        artifact_lookup: Dict[str, Dict[str, Any]] = {
            pkg.get("id"): pkg for pkg in packages if pkg.get("id")
        }

        vuln_by_package = {}
        for vuln in vulnerabilities:
            pkg_name = vuln.get("artifact", {}).get("name", "unknown")
            if pkg_name not in vuln_by_package:
                vuln_by_package[pkg_name] = []
            vuln_by_package[pkg_name].append(vuln)

        detailed_packages = []
        for pkg in packages:
            pkg_name = pkg.get("name", "unknown")
            pkg_version = pkg.get("version", "unknown")
            pkg_type = pkg.get("type", "unknown")

            pkg_vulns = vuln_by_package.get(pkg_name, [])

            for vuln in pkg_vulns:
                vuln_info = vuln.get("vulnerability", {})
                detailed_packages.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "type": pkg_type,
                    "vulnerability_id": vuln_info.get("id", "N/A"),
                    "severity": vuln_info.get("severity", "unknown"),
                    "fixed_version": vuln.get("vulnerability", {}).get("fix", {}).get("versions", ["Not available"])[0]
                    if vuln.get("vulnerability", {}).get("fix", {}).get("versions")
                    else "Not available"
                })

            if not pkg_vulns:
                detailed_packages.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "type": pkg_type,
                    "vulnerability_id": "None",
                    "severity": "None",
                    "fixed_version": "N/A"
                })

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "negligible": 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get("vulnerability", {}).get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        dependency_graph = []
        relationships = sbom_data.get("artifactRelationships", [])
        max_relationships = 10000

        print(f"      [info] Processing {len(relationships)} relationships for dependency graph...")

        for rel in relationships[:max_relationships]:
            if not isinstance(rel, dict):
                continue

            rel_type = str(rel.get("type", "")).lower()
            if rel_type in ["", "unknown"]:
                continue

            parent_ref = rel.get("parent", {})
            child_ref = rel.get("child", {})

            def describe(ref: Dict[str, Any]) -> str:
                ref_id: Optional[str] = None

                if isinstance(ref, str):
                    ref_id = ref
                elif isinstance(ref, dict):
                    ref_id = ref.get("id") or ref.get("artifact", {}).get("id")

                if not ref_id:
                    return "unknown"

                artifact = artifact_lookup.get(ref_id, {})
                name = artifact.get("name")
                version = artifact.get("version")

                if name:
                    return f"{name}@{version}" if version else name

                return ref_id

            parent_name = describe(parent_ref)
            child_name = describe(child_ref)

            if parent_name != "unknown" and child_name != "unknown":
                dependency_graph.append({
                    "type": rel.get("type", "UNKNOWN"),
                    "parent": parent_name,
                    "child": child_name
                })

        print(f"      [info] Built dependency graph with {len(dependency_graph)} relationships")
        if len(relationships) > max_relationships:
            print(f"      [info] Limited dependency graph to first {max_relationships} relationships for performance\n")

        return {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "summary": {
                "total_packages": len(packages),
                "total_vulnerabilities": len(vulnerabilities),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "negligible": severity_counts["negligible"]
            },
            "packages": detailed_packages,
            "dependency_graph": dependency_graph
        }

    def _save_json_report(self, scan_id: str, report_data: dict):
        json_path = Config.REPORTS_DIR / f"{scan_id}.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    def _save_csv_report(self, scan_id: str, report_data: dict):
        csv_path = Config.REPORTS_DIR / f"{scan_id}.csv"

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            fieldnames = [
                "scan_id",
                "target",
                "timestamp",
                "package",
                "version",
                "type",
                "vulnerability_id",
                "severity",
                "fixed_version",
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for pkg in report_data["packages"]:
                row = dict(pkg)
                row["scan_id"] = report_data.get("scan_id")
                row["target"] = report_data.get("target")
                row["timestamp"] = report_data.get("timestamp")
                writer.writerow(row)

    def get_report(self, scan_id: str) -> Optional[dict]:
        json_path = Config.REPORTS_DIR / f"{scan_id}.json"

        if not json_path.exists():
            print(f"Report not found: {scan_id}")
            return None

        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_reports(self) -> List[str]:
        reports = [f.stem for f in Config.REPORTS_DIR.glob("*.json")]
        return sorted(reports, reverse=True)


def print_report_summary(report: Dict[str, Any]):
    print("\n" + "=" * 60)
    print("REPORT SUMMARY")
    print("=" * 60)

    print(f"\nScan ID: {report['scan_id']}")
    print(f"Target: {report['target']}")
    print(f"Timestamp: {report['timestamp']}")
    print(f"\nSummary:")
    print(f"  - Total Packages: {report['summary']['total_packages']}")
    print(f"  - Total Vulnerabilities: {report['summary']['total_vulnerabilities']}")
    print(f"  - Critical: {report['summary']['critical']}")
    print(f"  - High: {report['summary']['high']}")
    print(f"  - Medium: {report['summary']['medium']}")
    print(f"  - Low: {report['summary']['low']}")

    if report.get("dependency_graph"):
        print(f"\nFirst 5 dependency edges:")
        for edge in report["dependency_graph"][:5]:
            print(f"  - {edge['parent']} -> {edge['child']} ({edge['type']})")

    print(f"\nFirst 5 packages with vulnerabilities:")
    for pkg in report["packages"][:5]:
        if pkg.get("vulnerability_id") != "None":
            print(f"  - {pkg['package']} ({pkg['version']}) - {pkg['severity']} - Fixed: {pkg['fixed_version']}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate SBOM and vulnerability reports for a given target."
    )
    parser.add_argument("target", nargs="?", help="Local path or GitHub repository URL to scan.")
    parser.add_argument("--cache", dest="use_cache", action="store_true", default=False, help="Enable repository caching.")
    parser.add_argument("--full-clone", action="store_true", help="Clone repositories with full history instead of a shallow clone.")
    parser.add_argument("--list-reports", action="store_true", help="List existing reports and exit.")
    parser.add_argument("--report-id", help="Show a previously generated report by scan ID.")
    parser.add_argument("--skip-vuln", dest="skip_vuln", action="store_true", help="Skip vulnerability scanning.")
    return parser.parse_args()


def main():
    args = parse_args()

    Config.init_directories()

    scanner = SBOMScanner(
        use_cache=args.use_cache,
        shallow_clone=not args.full_clone,
        skip_vuln=args.skip_vuln,
    )
    print("[ok] SBOM Scanner ready!")
    if args.skip_vuln:
        print("[info] Vulnerability scanning is disabled (SBOM only - faster)")
    else:
        print("[info] Full scan enabled: SBOM + Vulnerability scanning")
    if args.use_cache:
        print("[info] Repository caching is enabled")
    print(f"[ok] Reports will be saved to: {Config.REPORTS_DIR}\n")

    if args.list_reports:
        print("=" * 60)
        print("AVAILABLE REPORTS")
        print("=" * 60)
        for report_id in scanner.list_reports():
            print(f"  - {report_id}")
        return

    if args.report_id:
        report = scanner.get_report(args.report_id)
        if not report:
            print(f"Report '{args.report_id}' not found.")
            sys.exit(1)
        print_report_summary(report)
        return

    if not args.target:
        print("Target repository or path is required.")
        sys.exit(1)

    scan_id = scanner.scan(args.target)

    if not scan_id:
        sys.exit(1)

    report = scanner.get_report(scan_id)
    if report:
        print_report_summary(report)

    print("\n" + "=" * 60)
    print("AVAILABLE REPORTS")
    print("=" * 60)
    for report_id in scanner.list_reports():
        print(f"  - {report_id}")


if __name__ == "__main__":
    main()