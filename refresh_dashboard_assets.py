from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def run_script(script_name: str) -> None:
    script_path = BASE_DIR / script_name
    print(f"[REFRESH] Running {script_path.name} ...")
    subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(BASE_DIR),
        check=True
    )


def main() -> None:
    run_script("export_sergey_dataset.py")
    run_script("sbom_analysis.py")
    run_script("sbom_ui_plus.py")
    print("[REFRESH] Analytics refresh complete.")


if __name__ == "__main__":
    main()