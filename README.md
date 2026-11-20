# SBOM Scanner Tool

Generate SBOM (Software Bill of Materials) and vulnerability reports for any GitHub repository or local path. Includes both a web UI and command-line interface. Reports are saved as JSON and CSV files with dependency tree data and vulnerability information.

## Features

- **SBOM Generation**: Generate comprehensive Software Bill of Materials using Syft
- **Vulnerability Scanning**: Scan for security vulnerabilities using Grype
- **Web UI**: Easy-to-use web interface for scanning repositories
- **Command-Line Interface**: Full-featured CLI for automation and scripting
- **Repository Caching**: Cache cloned repositories for faster repeat scans
- **Progress Tracking**: Real-time progress indicators and timing information
- **Multiple Report Formats**: JSON and CSV output formats
- **Dependency Graph**: Visualize package dependencies

## Prerequisites

- **Python 3.11+** and `pip`
- **Git** (tested with Git for Windows 2.51+). The scanner will auto-detect Git in common install paths, but adding it to `PATH` is recommended.
- **Syft** and **Grype** binaries (included in `sbom-tools/syft/` and `sbom-tools/grype/` directories)
  - If you move them, set `SYFT_PATH` and `GRYPE_PATH` environment variables

## Setup

1. **Create and activate a virtual environment** (optional but recommended):
   ```powershell
   cd "C:\New folder"
   python -m venv venv
   .\venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```
   
   Or install individually:
   ```powershell
   pip install flask waitress
   ```

3. **Verify tools are available**:
   ```powershell
   git --version
   sbom-tools\syft\syft.exe version
   sbom-tools\grype\grype.exe version
   ```

## Web UI Usage

### Starting the Server

1. **Start the server** (from PowerShell, inside the activated venv if you created one):
   ```powershell
   python "C:\New folder\ui_app.py"
   ```

   The server will automatically:
   - Use **Waitress** (production WSGI server) if available - handles long-running scans without timeout issues
   - Fall back to Flask dev server if Waitress is not installed (with a warning about 120-second timeout limit)

2. **Open your browser** and navigate to `http://127.0.0.1:5000`

3. **Run a scan**:
   - Paste a repository URL (e.g., `https://github.com/opencv/opencv`)
   - Or enter a local path
   - Check "Use cache" to keep a local copy for faster repeat scans
   - Click "Run Scan"

### Web UI Features

- **Real-time Progress**: See scanning progress with timing information
- **Report Summary**: View vulnerability counts and package information
- **Dependency Tree**: Interactive dependency visualization
- **Download Reports**: Download JSON and CSV reports
- **Report History**: List and view previous scans

## Command-Line Usage

### Basic Scan

```powershell
python "C:\New folder\sbom-tools\sbom.py" https://github.com/opencv/opencv
```

This will:
1. Clone the repository (if GitHub URL)
2. Generate SBOM
3. Scan for vulnerabilities
4. Create JSON and CSV reports
5. Display a summary

### Command-Line Options

```powershell
# Use repository caching (faster for repeated scans)
python "C:\New folder\sbom-tools\sbom.py" https://github.com/opencv/opencv --cache

# Skip vulnerability scanning (faster, SBOM only)
python "C:\New folder\sbom-tools\sbom.py" https://github.com/opencv/opencv --skip-vuln

# Use full clone instead of shallow clone
python "C:\New folder\sbom-tools\sbom.py" https://github.com/opencv/opencv --full-clone

# List all available reports
python "C:\New folder\sbom-tools\sbom.py" --list-reports

# View a specific report
python "C:\New folder\sbom-tools\sbom.py" --report-id opencv-opencv

# Combine options
python "C:\New folder\sbom-tools\sbom.py" https://github.com/opencv/opencv --cache --skip-vuln
```

### Command-Line Options Reference

| Option | Description |
|--------|-------------|
| `--cache` | Enable repository caching (reuse local clone between scans) |
| `--skip-vuln` | Skip vulnerability scanning (faster, only generates SBOM) |
| `--full-clone` | Clone repositories with full history instead of shallow clone |
| `--list-reports` | List existing reports and exit without running a new scan |
| `--report-id <id>` | Show a previously generated report by scan ID |

## Output

### Report Files (Local Storage)

Reports are automatically saved in the `reports/` directory:

- **Location**: `C:\New folder\reports\`
- **JSON Report**: `reports/<scan-id>.json`
  - Complete scan data including packages, vulnerabilities, dependency graph
  - Structured format for programmatic access
  - **View**: Open with any text editor or download from Web UI
  
- **CSV Report**: `reports/<scan-id>.csv`
  - Tabular format with package and vulnerability information
  - Easy to import into spreadsheets or databases
  - **View**: Open with Excel, Notepad, or download from Web UI

**To view files in PowerShell** (path has spaces, so use quotes):
```powershell
# Navigate to reports folder
cd "C:\New folder\reports"

# List all report files
dir

# Or list only JSON files
dir *.json

# Or list only CSV files
dir *.csv

# Open a specific file in default application
Start-Process "opencv-opencv.json"
Start-Process "opencv-opencv.csv"

# Or open folder in Windows Explorer
explorer "C:\New folder\reports"
```


### Report Contents

Each report includes:

- **Summary**:
  - Total packages found
  - Total vulnerabilities found
  - Vulnerability counts by severity (Critical, High, Medium, Low, Negligible)

- **Package Details**:
  - Package name, version, and type
  - Associated vulnerabilities (if any)
  - Fixed versions (if available)

- **Dependency Graph**:
  - Package dependency relationships
  - Parent-child relationships

## Performance Tips

### For Large Repositories

Large repositories (like OpenCV, OpenSSL, Mozilla Firefox) can take significant time to scan:

- **SBOM Generation**: 5-15 minutes
- **Vulnerability Scanning**: 10-30 minutes
- **Total Time**: 20-40 minutes for full scan

**To speed up scans:**

1. **Use `--skip-vuln`** for SBOM-only scans (5-10 minutes)
2. **Use `--cache`** for faster repeat scans (skips cloning)
3. **Use shallow clones** (default, faster than full clones)
4. **Start with smaller repositories** to test the setup

### Example: Fast SBOM-Only Scan

```powershell
python "C:\New folder\sbom-tools\sbom.py" https://github.com/opencv/opencv --skip-vuln --cache
```

This will:
- Skip vulnerability scanning (saves 10-30 minutes)
- Use cached repository if available (saves cloning time)
- Complete in ~5-10 minutes instead of 20-40 minutes

## Troubleshooting

### Server Timeout Issues

**Problem**: Connection reset errors (`ERR_CONNECTION_RESET`) when scanning large repositories.

**Cause**: Flask development server has a 120-second timeout limit. Large repositories can take 10-15+ minutes to scan.

**Solution**: Install and use Waitress (production WSGI server):
```powershell
pip install waitress
python "C:\New folder\ui_app.py"
```

Waitress has no timeout limit and handles long-running requests much better.

### Common Errors

#### `'SBOMScanner' object has no attribute 'get_report'`

**Solution**: 
1. Stop the Flask server (Ctrl+C)
2. Clear Python cache:
   ```powershell
   Get-ChildItem -Path . -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force
   ```
3. Restart the server

#### `ERR_FILE_NOT_FOUND`

**Solution**: Usually a browser caching issue. Try:
- Hard refresh (Ctrl+F5)
- Clear browser cache
- Restart the server

#### `Git executable not found`

**Solution**: 
- Install Git: https://git-scm.com/download/win
- Or add Git to your system PATH
- The scanner will also check common Windows installation paths automatically

#### `Syft not found` or `Grype not found`

**Solution**:
- Verify the tools exist in `sbom-tools/syft/` and `sbom-tools/grype/`
- Or set environment variables:
  ```powershell
  $env:SYFT_PATH="C:\path\to\syft.exe"
  $env:GRYPE_PATH="C:\path\to\grype.exe"
  ```

#### Scan fails silently

**Solution**:
- Check the server console output for detailed error messages
- Verify the repository URL is correct and accessible
- Check that you have sufficient disk space
- For private repositories, ensure you have proper authentication

### Getting Help

- Check the server console for detailed error messages
- Verify all prerequisites are installed correctly
- Test with a small repository first (e.g., `https://github.com/gin-gonic/gin`)
- Review the scan logs in the terminal output

## Project Structure

```
C:\New folder\
├── sbom-tools/
│   ├── sbom.py              # Main scanner module
│   ├── syft/                # Syft binary
│   └── grype/               # Grype binary
├── ui/
│   ├── templates/           # HTML templates
│   └── static/              # CSS, JavaScript
├── reports/                 # Generated reports (JSON/CSV files)
│   ├── <scan-id>.json       # JSON format reports
│   └── <scan-id>.csv        # CSV format reports
├── temp/                    # Temporary files (created automatically)
├── repo-cache/              # Cached repositories (created automatically)
├── ui_app.py                # Flask web application
├── view_reports.ps1         # PowerShell script to view reports
├── requirements.txt         # Python dependencies
└── README.md                # This file
```

### Where to Find Your Scan Files

**Local Files**: `C:\New folder\reports\`
   - JSON files: `<scan-id>.json`
   - CSV files: `<scan-id>.csv`
   - View directly or download from Web UI

## License

This project uses open-source tools:
- **Syft**: Apache License 2.0
- **Grype**: Apache License 2.0

## Contributing

When contributing, please:
- Test with both small and large repositories
- Ensure all tests pass
- Update documentation as needed
- Follow existing code style

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review server console output for errors
3. Test with a known working repository first
