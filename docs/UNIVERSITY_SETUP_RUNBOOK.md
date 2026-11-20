# Runbook: Fresh Setup on the University Proxmox Windows Machine

This runbook takes a brand-new Windows machine from nothing to a running platform, then runs the
**University of XYZ case study**: scanning all 14 systems, recording the data dependencies from the
diagram, and visualizing the impact. Everything needed is in this repository.

Open this file on GitHub in the new machine's browser and work through it from top to bottom.
Tick each box as you go.

---

## Before you start: things to bring (not stored in GitHub)

- [ ] Your **GitHub sign-in** (tejasai1), to clone this private repository.
- [ ] Your **Meta model API key**, for the AI features. Keep it in a password manager, not in a file
      or an email.
- [ ] The **Python version** used on the laptop: `________` (fill this in before switching machines;
      the laptop command is `.\venv\Scripts\python.exe --version`).

---

## Part A: Install the programs

Install in this order.

| # | Program | Version | Download | During install |
|---|---|---|---|---|
| 1 | Git for Windows | 2.51 or newer | https://git-scm.com/download/win | Keep the defaults. |
| 2 | Python | Same as the laptop, at least 3.11 | https://www.python.org/downloads/windows/ | Tick **Add python.exe to PATH** on the first screen. |
| 3 | MySQL Server 8.0 + Workbench | 8.0 | https://dev.mysql.com/downloads/installer/ | Choose **Server** and **Workbench**. Set a root password and write it down safely. Keep **Start the MySQL Server at System Startup** ticked. |
| 4 | Visual Studio Code (optional) | Latest | https://code.visualstudio.com/ | Tick **Add to PATH**, so the `code` command works. Notepad also works. |

Syft and Grype are added in Part D, after cloning.

**Check the installs.** Open a **new** PowerShell window (so it sees the new PATH) and run:

```powershell
git --version
python --version
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" --version
```

All three should print a version number.

---

## Part B: Get the project

```powershell
mkdir C:\Capstone
cd C:\Capstone
git clone https://github.com/tejasai1/sbom-data-dependency-monitor.git
cd sbom-data-dependency-monitor
```

The first clone opens a GitHub sign-in window. Choose **Sign in with your browser** and approve it.

From here on, every command runs inside `C:\Capstone\sbom-data-dependency-monitor`.

---

## Part C: Python environment

```powershell
python -m venv venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

- `Set-ExecutionPolicy` is needed **once per PowerShell window**. If asked to confirm, type `Y`.
- After `activate`, the prompt starts with `(venv)`.
- The install takes a few minutes.

---

## Part D: Syft and Grype

1. Download these two files:
   - Syft 1.17.0: https://github.com/anchore/syft/releases/tag/v1.17.0, file `syft_1.17.0_windows_amd64.zip`
   - Grype 0.84.0: https://github.com/anchore/grype/releases/tag/v0.84.0, file `grype_0.84.0_windows_amd64.zip`
2. Unzip them into the project:

```powershell
Expand-Archive "$HOME\Downloads\syft_1.17.0_windows_amd64.zip" sbom-tools\syft -Force
Expand-Archive "$HOME\Downloads\grype_0.84.0_windows_amd64.zip" sbom-tools\grype -Force
sbom-tools\syft\syft.exe version
sbom-tools\grype\grype.exe version
```

The two version commands should print **1.17.0** and **0.84.0**. If a browser saved a file with
`(1)` in its name, use that name in the command.

---

## Part E: Database

This machine is a clean instance for the case study, so create the database with the case study name:

```powershell
$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"
& $mysql -u root -p -e "CREATE DATABASE sbom_university_xyz"
& $mysql -u root -p sbom_university_xyz -e "source sql/schema.sql"
& $mysql -u root -p sbom_university_xyz -e "source sql/app_settings_data.sql"
& $mysql -u root -p sbom_university_xyz -e "SHOW TABLES"
```

Enter the MySQL root password each time. The last command should list **10 tables**:
`app_settings`, `data_dependency`, `impact_report`, `monitor_log`, `monitored_targets`,
`package_vuln_observation`, `packages_name`, `scan`, `suggested_dependency`, `vulnerability`.

---

## Part F: Private settings

These files hold secrets. They are listed in `.gitignore`, so they are never uploaded.

**1. Database connection**

```powershell
Copy-Item tejasai_db_config.example.py tejasai_db_config.py
code tejasai_db_config.py
```

In the file:
- replace `your_password_here` with the MySQL root password;
- change the database name to **`sbom_university_xyz`**;
- save with **Ctrl + S**.

**2. Model API key**

```powershell
code .env
```

Type one line, using your real key, and save:

```
MODEL_API_KEY=your_key_here
```

---

## Part G: Start the platform

```powershell
python ui_app.py
```

Open **http://127.0.0.1:5050** in the browser. The dashboard should open with no repositories.

To stop the server: click in the PowerShell window and press **Ctrl + C**.

**Every time you come back** (new PowerShell window):

```powershell
cd C:\Capstone\sbom-data-dependency-monitor
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\venv\Scripts\activate
python ui_app.py
```

MySQL starts by itself with Windows, so it needs no command.

**Optional: keep the auto-scan from re-scanning during the case study.** In the **Settings** tab,
set the auto-scan interval to **1 day** and save.

---

## Part H: Case study: University of XYZ

Research question: *How does the data flow between vulnerable systems spread the impact of vulnerabilities?*

### H1. Add the 14 systems

1. Open the **Initial Population** tab.
2. Use **Import File** and choose `case_study\university_xyz_targets.json` from the project folder.
3. Click **Refresh**. The table should show **14 targets**, all active, with source `university_xyz`.

| System | Repository |
|---|---|
| Moodle (LMS) | https://github.com/moodle/moodle |
| openSIS (Student Registration) | https://github.com/OS4ED/openSIS-Classic |
| OrangeHRM (HR Records) | https://github.com/orangehrm/orangehrm |
| Nextcloud (Document Management) | https://github.com/nextcloud/server |
| Proxmox VE (Private Cloud) | https://github.com/proxmox/pve-manager |
| ERPNext (Accounting) | https://github.com/frappe/erpnext |
| Keycloak (Single Sign-On) | https://github.com/keycloak/keycloak |
| Koha (Library Management) | https://github.com/Koha-Community/Koha |
| GLPI (Helpdesk and Asset Tracking) | https://github.com/glpi-project/glpi |
| CiviCRM (Admissions and Alumni CRM) | https://github.com/civicrm/civicrm-core |
| Mattermost (Real-Time Chat) | https://github.com/mattermost/mattermost |
| BigBlueButton (Video Classroom) | https://github.com/bigbluebutton/bigbluebutton |
| DSpace (Research Repository) | https://github.com/DSpace/DSpace |
| LibreBooking (Room and Event Scheduling) | https://github.com/LibreBooking/app |

### H2. Scan all 14 systems

1. In **Initial Population**, click **Scan All Active Targets**.
2. Leave it running. Large systems such as Nextcloud, Moodle, Mattermost and Keycloak can take a
   long time each. The first scan also downloads Grype's vulnerability database.
3. Watch the PowerShell window for progress or errors.
4. When it finishes, open the **Dashboard** and check that all 14 systems show a scan.

If one system fails, scan it again on its own with the scan button in its row.

### H3. Check scan coverage, and swap a system only if needed

Write down, for each system, the number of packages and vulnerabilities found.

| System | Packages | Vulnerabilities (critical / high / medium / low) | Notes |
|---|---|---|---|
| | | | |

If **Proxmox VE** or **Koha** comes back with **0 packages**, the scanner could not read it
(both are mostly Perl). Then, as agreed with the professor, use the alternative:

| Original | Alternative | Repository |
|---|---|---|
| Proxmox VE | Apache CloudStack (private cloud) | https://github.com/apache/cloudstack |
| Koha | Invenio ILS (library management) | https://github.com/inveniosoftware/invenio-app-ils |

To swap: in **Initial Population**, add the alternative as a new target (type `github_repo`,
source `university_xyz`), scan it, and set the original to inactive. Use the alternative in its
place in every data dependency in H4, and note the swap in the report.

### H4. Record the 33 data dependencies

In the **Data Dependencies** tab, **step 1:** choose the system on the left; **step 2:** tick every
system it **gets data from**; then save. Do this for each system below.

| Choose this system (step 1) | Tick these systems it gets data from (step 2) |
|---|---|
| Proxmox VE | nothing |
| Keycloak | Proxmox VE |
| CiviCRM | Proxmox VE, Keycloak |
| openSIS | Proxmox VE, Keycloak, CiviCRM, Moodle |
| OrangeHRM | Proxmox VE, Keycloak |
| DSpace | Proxmox VE, Keycloak |
| ERPNext | Proxmox VE, Keycloak, openSIS, OrangeHRM, Koha |
| Moodle | Proxmox VE, CiviCRM, openSIS |
| Nextcloud | Proxmox VE, OrangeHRM, ERPNext |
| LibreBooking | Proxmox VE, openSIS, OrangeHRM |
| Mattermost | Proxmox VE, ERPNext |
| BigBlueButton | Proxmox VE, ERPNext |
| Koha | Proxmox VE, Moodle |
| GLPI | Proxmox VE, Moodle |

The tab lists systems by repository name: Proxmox VE is `proxmox/pve-manager`, Keycloak is
`keycloak/keycloak`, openSIS is `OS4ED/openSIS-Classic`, ERPNext is `frappe/erpnext`, and so on (see
the table in H1).

That is **33 links** in total. The full list with the data each link carries (taken from the
case study diagram) is in `case_study\university_xyz_data_dependencies.csv`:

- Proxmox VE hosts all 13 other systems, so if Proxmox is compromised, every system is.
- Keycloak gives SSO and identity sync to CiviCRM, openSIS, ERPNext, OrangeHRM and DSpace. It
  reaches the other systems through these five.
- CiviCRM sends admitted student data to Moodle, and has an unlabelled link to openSIS.
- openSIS sends course rosters to Moodle, tuition billing to ERPNext, and schedules to LibreBooking.
- Moodle sends final grades to openSIS, borrowing privileges to Koha, and IT tickets to GLPI.
- OrangeHRM sends payroll and tax to ERPNext, contracts to Nextcloud, and room schedules to LibreBooking.
- ERPNext sends audits and invoices to Nextcloud, and virtual classroom data to Mattermost and BigBlueButton.
- Koha sends fees and fines to ERPNext.

**Check:** open Proxmox VE's tree. Its downstream side should reach all 13 systems at 1 hop.

### H5. Visualize the impact

For each of these four systems, open the **Data Flow Tree** and generate the **AI impact report**:

| System | Why it matters |
|---|---|
| Proxmox VE | Infrastructure: a compromise reaches every system. |
| Keycloak | Identity hub: reaches most systems in 1 to 3 hops through the five SSO systems. |
| openSIS | In the middle: gets data from CiviCRM and Moodle and sends to four systems. |
| ERPNext | Collects money and HR data from four systems, and sends to three. |

For each one:
1. Take a screenshot of the tree (**Windows + Shift + S**).
2. Generate the AI impact report, check that the green "verified" badge appears, and take a
   screenshot of the report.
3. Fill in the results table:

| System | Upstream systems | Downstream systems reached | Max hops | Vulnerabilities on the downstream path | AI risk level |
|---|---|---|---|---|---|
| Proxmox VE | | | | | |
| Keycloak | | | | | |
| openSIS | | | | | |
| ERPNext | | | | | |

Also try a **leaf system** such as GLPI or DSpace, which should show no downstream systems, as a
comparison.

### H6. Optional: find links in code

On two or three systems (for example openSIS, Moodle and ERPNext), open **Suggested Data Flows**
and click **Find flows in code**. Most of these links are set up by configuration rather than in
code, so few or no suggestions is a valid result. It supports the limitation stated in the
report's conclusion.

### H7. Save the results

Save the screenshots and the filled-in tables somewhere you can reach from the documentation
machine, for example a OneDrive folder or an email to yourself. They go into the report's new
case study section.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` in this window, then activate again. |
| `git`, `python` or `code` is not recognized | Close PowerShell and open a new window. If it still fails, reinstall with **Add to PATH** ticked. |
| `Can't connect to MySQL server` | Open **Services** (Windows key, type `services`), find **MySQL80**, and click **Start**. |
| `Access denied for user 'root'` | The password in `tejasai_db_config.py` does not match the MySQL root password. |
| `Unknown database` | The database name in `tejasai_db_config.py` does not match `sbom_university_xyz`. |
| `Syft not found` or `Grype not found` | Check that the files are at `sbom-tools\syft\syft.exe` and `sbom-tools\grype\grype.exe` (see Part D). |
| Pip fails to install a package | The Python version is probably newer than the laptop's. Install the laptop's version and redo Part C. |
| A scan fails for one repository | Scan it again on its own. Check the internet connection and the error in the PowerShell window. |
| AI report or Find flows gives an API error | Check that `.env` has `MODEL_API_KEY=` with the real key, and that the machine can reach `api.meta.ai`. |
| Port 5050 already in use | Another copy of the app is running. Close the other PowerShell window, or press Ctrl + C there. |

---

## Saving changes back to GitHub (optional)

If you change any project files on this machine:

```powershell
git status
git add .
git commit -m "Describe the change"
git push
```

`git status` should never list `.env` or `tejasai_db_config.py`. If it does, stop and do not commit.
