# SBoM Monitoring Platform with Data Dependencies

Capstone project: *Developing Automated Tools to Use Software Bills of Materials for Vulnerability Monitoring*
Tejasai Kola, MS Computer Science, Western New England University. Advisor: Dr. Sergey Butakov.

The platform scans software repositories with Syft and Grype, stores their packages and
vulnerabilities in MySQL, and monitors them over time. On top of that it records **data
dependencies** between systems (which system uses data that another creates or changes), traces
them upstream and downstream, and uses a language model component, **FlowTrace**, to suggest data
links from source code and to write impact reports.

## Features

- **Scanning and monitoring:** SBoM and vulnerability scans of GitHub repositories or local
  folders, repeated automatically on an interval set in the Settings tab.
- **Data dependency recording and tracing:** a manager records which systems get data from which;
  the platform shows each system's upstream and downstream tree with hop counts and the latest
  vulnerability summary of every system in it.
- **AI-suggested data dependencies:** FlowTrace reads a system's code and suggests data links with
  the exact lines of code as evidence. Nothing is recorded until a manager approves it.
- **AI impact report:** explains which systems could be affected if a system is compromised, using
  only facts from the database. Every system and vulnerability ID in a report is checked against
  those facts before it is shown.
- **Code evidence:** every link found in code can be opened to show the lines that prove it.

## Requirements

| Software | Version used |
|---|---|
| Windows 10/11 or Windows Server | |
| Python | 3.11 or newer |
| MySQL Server (with MySQL Workbench, optional) | 8.0 |
| Git for Windows | 2.51 |
| Syft | 1.17.0 |
| Grype | 0.84.0 |
| A model API key (Meta Model API by default) | needed only for the AI features |

## Setup on a new machine

All commands are for PowerShell.

### 1. Clone the repository

```powershell
git clone https://github.com/tejasai1/sbom-data-dependency-monitor.git
cd sbom-data-dependency-monitor
```

The repository is private, so Git asks you to sign in to GitHub the first time.

### 2. Create the Python environment

```powershell
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\activate
pip install -r requirements.txt
```

`Set-ExecutionPolicy` is needed once per PowerShell window, so the activate script is allowed to run.

### 3. Add Syft and Grype

The scanner programs are not stored in the repository. Download the Windows versions from Anchore:

- Syft 1.17.0: https://github.com/anchore/syft/releases/tag/v1.17.0 (file `syft_1.17.0_windows_amd64.zip`)
- Grype 0.84.0: https://github.com/anchore/grype/releases/tag/v0.84.0 (file `grype_0.84.0_windows_amd64.zip`)

Unzip them so the programs are at:

```
sbom-tools\syft\syft.exe
sbom-tools\grype\grype.exe
```

Check them:

```powershell
sbom-tools\syft\syft.exe version
sbom-tools\grype\grype.exe version
```

Grype downloads its vulnerability database on the first scan, so the machine needs internet access.

### 4. Create the database

Create an empty database and load the table structure (10 tables) and the default Settings row.
Change the database name if you want a separate database, for example for a new case study.

```powershell
$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"
& $mysql -u root -p -e "CREATE DATABASE sbom_monitoring_tejasai"
& $mysql -u root -p sbom_monitoring_tejasai -e "source sql/schema.sql"
& $mysql -u root -p sbom_monitoring_tejasai -e "source sql/app_settings_data.sql"
```

### 5. Add the private settings

These two files hold secrets and are never committed (they are listed in `.gitignore`).

**Database connection:** copy the example file and fill in your MySQL details:

```powershell
Copy-Item tejasai_db_config.example.py tejasai_db_config.py
code tejasai_db_config.py
```

Set the password, and the database name if you used a different one in step 4.

**Model API key** (only for the AI features): create a file called `.env` in the main folder with one line:

```
MODEL_API_KEY=your_key_here
```

The provider and model are set in `config.yaml` (Muse Spark through the Meta Model API by default).
Any OpenAI-compatible service, including a model running on the organization's own servers, can be
used by changing `config.yaml`. FlowTrace skips secret files such as `.env` when it reads code, so
no credentials are sent to the model.

### 6. Start the platform

```powershell
python ui_app.py
```

Open http://127.0.0.1:5050 in a browser. Stop the server with **Ctrl + C**.

## Using the platform

1. **Add and scan systems:** add a GitHub repository URL or a local folder and run a scan.
2. **Record data dependencies:** in the Data Dependencies tab, choose a system and tick the systems
   it gets data from or sends data to, then save.
3. **Find links in code (optional):** in Suggested Data Flows, click *Find flows in code*, then
   approve or reject each suggestion.
4. **See the impact:** open a system's Data Flow Tree to see its upstream and downstream systems,
   and generate an AI impact report.
5. **Monitoring:** set the auto-scan interval in the Settings tab.

## Project structure

```
ui_app.py                 Flask application: dashboard, REST API, auto-scan loop
dependency_routes.py      Recording and tracing data dependencies
settings_routes.py        Auto-scan interval settings
impact_routes.py          AI impact report
discovery_routes.py       Suggested data flows from code and code evidence
tejasai_db_config.example.py  Template for the database connection settings
config.yaml               Language model provider and model
sbom-tools/
  sbom.py                 Runs Syft and Grype and writes JSON and CSV reports
  db_storage.py           Saves scan results to MySQL
  db_monitor_job.py       Compares each scan with the previous one
flowtrace/                Language model component (FlowTrace)
  providers/              Model connection (OpenAI-compatible) and config loading
  reader.py, extractor.py Reads code and extracts data flows
  capstone_facts.py       Builds facts for a system from the MySQL database
  capstone_impact.py      Writes and checks the impact report
  capstone_discovery.py   Turns flows found in code into suggested dependencies
  report_store.py         Saves impact reports
  suggestion_store.py     Saves suggestions, approvals and code evidence
ui/templates/index.html   Dashboard page
ui/static/                Dashboard JavaScript and CSS
sql/schema.sql            Table structure for a new database
sql/app_settings_data.sql Default auto-scan setting
```

## Related repository

FlowTrace was first built as a prototype during the Meta Global AI Developer Hackathon
(October 27 to November 4, 2026) as the language model part of this capstone:
https://github.com/tejasai1/Flowtrace

## Licenses of the tools used

Syft and Grype are Apache License 2.0 projects by Anchore. vis-network, used to draw the data flow
trees, is available under the Apache License 2.0 / MIT.
