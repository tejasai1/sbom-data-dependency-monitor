let form, targetInput, useCacheInput, shallowCloneInput, statusEl;
let summaryEl, tableBody, dependencyTreeEl, reportsLinksEl;
let monitorTableBody, monitorStatusEl, refreshMonitorBtn;
let datasetTableBody, refreshDatasetBtn, scanAllActiveBtn, populationActionStatus;
let dashTotalTargets, dashActiveTargets, dashTotalScans, dashTotalVulns;
let latestScanTableBody, historyScanTableBody, historyMonitorTableBody;
let healthActiveCount, healthInactiveCount, healthMonitorCount, lastUpdatedText;
let addTargetForm, addTargetStatus, targetSearchInput, targetFilterSelect;
let importFileForm, importFileInput, importJsonTextForm, importJsonText, importStatus;
let importHistoryTableBody, importHistoryShell, importHistoryEmpty;
let summaryActiveCount, summaryInactiveCount, summarySourceCount, summaryTypeCount;
let summaryBySource, summaryByType;
let refreshAnalyticsBtn, reloadAnalyticsFrameBtn, analyticsFrame, analyticsStatus;

window._datasetRows = [];
window._monitorRows = [];
window._latestScanRows = [];
window._importHistory = [];

function initElements() {
  form = document.getElementById("scan-form");
  targetInput = document.getElementById("target-input");
  useCacheInput = document.getElementById("use-cache");
  shallowCloneInput = document.getElementById("shallow-clone");
  statusEl = document.getElementById("status");

  summaryEl = document.getElementById("summary");
  tableBody = document.querySelector("#vulnerability-table tbody");
  dependencyTreeEl = document.getElementById("dependency-tree");
  reportsLinksEl = document.getElementById("reports-links");

  monitorTableBody = document.querySelector("#monitor-table tbody");
  monitorStatusEl = document.getElementById("monitor-status");
  refreshMonitorBtn = document.getElementById("refresh-monitor");

  datasetTableBody = document.querySelector("#dataset-table tbody");
  refreshDatasetBtn = document.getElementById("refresh-dataset");
  scanAllActiveBtn = document.getElementById("scan-all-active");
  populationActionStatus = document.getElementById("population-action-status");

  dashTotalTargets = document.getElementById("dash-total-targets");
  dashActiveTargets = document.getElementById("dash-active-targets");
  dashTotalScans = document.getElementById("dash-total-scans");
  dashTotalVulns = document.getElementById("dash-total-vulns");

  latestScanTableBody = document.querySelector("#latest-scan-table tbody");
  historyScanTableBody = document.querySelector("#history-scan-table tbody");
  historyMonitorTableBody = document.querySelector("#history-monitor-table tbody");

  healthActiveCount = document.getElementById("health-active-count");
  healthInactiveCount = document.getElementById("health-inactive-count");
  healthMonitorCount = document.getElementById("health-monitor-count");
  lastUpdatedText = document.getElementById("last-updated-text");

  addTargetForm = document.getElementById("add-target-form");
  addTargetStatus = document.getElementById("add-target-status");
  targetSearchInput = document.getElementById("target-search");
  targetFilterSelect = document.getElementById("target-filter");

  importFileForm = document.getElementById("import-file-form");
  importFileInput = document.getElementById("import-file");
  importJsonTextForm = document.getElementById("import-json-text-form");
  importJsonText = document.getElementById("import-json-text");
  importStatus = document.getElementById("import-status");

  importHistoryTableBody = document.querySelector("#import-history-table tbody");
  importHistoryShell = document.getElementById("import-history-shell");
  importHistoryEmpty = document.getElementById("import-history-empty");

  summaryActiveCount = document.getElementById("summary-active-count");
  summaryInactiveCount = document.getElementById("summary-inactive-count");
  summarySourceCount = document.getElementById("summary-source-count");
  summaryTypeCount = document.getElementById("summary-type-count");
  summaryBySource = document.getElementById("summary-by-source");
  summaryByType = document.getElementById("summary-by-type");

  refreshAnalyticsBtn = document.getElementById("refresh-analytics");
  reloadAnalyticsFrameBtn = document.getElementById("reload-analytics-frame");
  analyticsFrame = document.getElementById("analytics-frame");
  analyticsStatus = document.getElementById("analytics-status");
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDateTime(value) {
  if (!value) return "—";
  const normalized = String(value).replace(" ", "T");
  const date = new Date(normalized);
  if (isNaN(date.getTime())) return escapeHtml(value);
  return date.toLocaleString();
}

function severityClass(severity) {
  const key = String(severity || "none").toLowerCase();
  if (key === "critical") return "severity-critical";
  if (key === "high") return "severity-high";
  if (key === "medium") return "severity-medium";
  if (key === "low") return "severity-low";
  if (key === "negligible") return "severity-negligible";
  return "severity-none";
}

// Scan times arrive like "Wed, 07 Oct 2026 16:15:57 GMT". They are the server's
// local time (Flask adds the "GMT" label), so the numbers are read as local time.
function parseServerTime(value) {
  const m = String(value || "").match(/(\d{1,2}) (\w{3}) (\d{4}) (\d{2}):(\d{2}):(\d{2})/);
  if (!m) return null;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = months.indexOf(m[2]);
  if (month < 0) return null;
  return new Date(Number(m[3]), month, Number(m[1]), Number(m[4]), Number(m[5]), Number(m[6]));
}

// Header badge: shows when the newest scan result arrived (not when the page refreshed).
function updateLastUpdatedText() {
  if (!lastUpdatedText) return;

  const scanRows = (window._latestScanRows && window._latestScanRows.length)
    ? window._latestScanRows
    : (window._monitorRows || []);
  const latest = scanRows.length ? parseServerTime(scanRows[0].scan_time) : null;

  if (!latest) {
    lastUpdatedText.textContent = scanRows.length ? "Connected" : "No scans yet";
  } else {
    const sameDay = latest.toDateString() === new Date().toDateString();
    lastUpdatedText.textContent = "Latest scan: " + (sameDay
      ? latest.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })
      : latest.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }));
  }

  (lastUpdatedText.closest(".topbar-status") || lastUpdatedText).title = "Data checked " + new Date().toLocaleTimeString();
  setLiveDot(true);
}

// Called when a refresh fails, so a stopped server doesn't look "live".
function markConnectionLost() {
  if (!lastUpdatedText) return;
  lastUpdatedText.textContent = "Server not reachable";
  (lastUpdatedText.closest(".topbar-status") || lastUpdatedText).title = "Last attempt " + new Date().toLocaleTimeString() + ". Retrying automatically.";
  setLiveDot(false);
}

// Green dot when connected, red when the server can't be reached.
function setLiveDot(isConnected) {
  const dot = document.querySelector(".topbar-status .live-dot");
  if (!dot) return;
  dot.style.background = isConnected ? "" : "#dc2626";
  dot.style.boxShadow = isConnected ? "" : "0 0 0 6px rgba(220, 38, 38, 0.14)";
}



function switchPanel(panelId) {
  document.querySelectorAll(".panel-screen").forEach(function(panel) {
    panel.classList.add("hidden-panel");
    panel.classList.remove("active-panel");
  });

  document.querySelectorAll(".nav-item").forEach(function(btn) {
    btn.classList.remove("active");
  });

  const panel = document.getElementById(panelId);
  const nav = document.querySelector('.nav-item[data-panel="' + panelId + '"]');

  if (panel) {
    panel.classList.remove("hidden-panel");
    panel.classList.add("active-panel");
  }

  if (nav) {
    nav.classList.add("active");
  }
}

function setupSidebarNavigation() {
  document.querySelectorAll(".nav-item").forEach(function(button) {
    button.addEventListener("click", function() {
      const panelId = this.getAttribute("data-panel");
      if (panelId) {
        switchPanel(panelId);
      }
    });
  });
}

function renderSummary(report) {
  const summary = report.summary || {};
  const scanId = escapeHtml(report.scan_id || "");
  const target = escapeHtml(report.target || "");
  const timestamp = formatDateTime(report.timestamp);
  const dbMessage = report.database_message || "";

  summaryEl.innerHTML =
    "<p><strong>Scan ID:</strong> " + scanId + "</p>" +
    "<p><strong>Target:</strong> " + target + "</p>" +
    "<p><strong>Timestamp:</strong> " + timestamp + "</p>" +
    "<div class='summary-grid'>" +
      "<div><strong>Total Packages:</strong><br>" + escapeHtml(summary.total_packages || 0) + "</div>" +
      "<div><strong>Total Vulnerabilities:</strong><br>" + escapeHtml(summary.total_vulnerabilities || 0) + "</div>" +
      "<div><strong>Level 1 Libraries:</strong><br>" + escapeHtml(summary.level_1_libraries || 0) + "</div>" +
      "<div><strong>Level 2 Libraries:</strong><br>" + escapeHtml(summary.level_2_libraries || 0) + "</div>" +
      "<div><strong>Critical:</strong><br>" + escapeHtml(summary.critical || 0) + "</div>" +
      "<div><strong>High:</strong><br>" + escapeHtml(summary.high || 0) + "</div>" +
      "<div><strong>Medium:</strong><br>" + escapeHtml(summary.medium || 0) + "</div>" +
      "<div><strong>Low:</strong><br>" + escapeHtml(summary.low || 0) + "</div>" +
      "<div><strong>Negligible:</strong><br>" + escapeHtml(summary.negligible || 0) + "</div>" +
    "</div>";

  const jsonName = scanId + ".json";
  const csvName = scanId + ".csv";

  reportsLinksEl.innerHTML =
    "<p>" +
      "<a href='/reports/" + encodeURIComponent(jsonName) + "' target='_blank'>Download JSON report</a>" +
      " | " +
      "<a href='/reports/" + encodeURIComponent(csvName) + "' target='_blank'>Download CSV report</a>" +
    "</p>" +
    (dbMessage
      ? "<div class='summary-box summary-box-inline'>" + escapeHtml(dbMessage) + "</div>"
      : "");
}

function renderTable(packages) {
  tableBody.innerHTML = "";

  if (!packages || packages.length === 0) {
    tableBody.innerHTML = "<tr><td colspan='6'>No packages found.</td></tr>";
    return;
  }

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    let vulnId = pkg.vulnerability_id || "None";
    const severity = pkg.severity || "None";
    const fixedVer = pkg.fixed_version || "N/A";

    if (vulnId === "None" || vulnId === "N/A") {
      let hasRealVuln = false;
      for (let j = 0; j < packages.length; j++) {
        if (
          packages[j].package === pkg.package &&
          packages[j].version === pkg.version &&
          packages[j].vulnerability_id &&
          packages[j].vulnerability_id !== "None" &&
          packages[j].vulnerability_id !== "N/A"
        ) {
          hasRealVuln = true;
          break;
        }
      }
      if (hasRealVuln) continue;
    }

    const row = document.createElement("tr");
    row.innerHTML =
      "<td>" + escapeHtml(pkg.package || "") + "</td>" +
      "<td>" + escapeHtml(pkg.version || "") + "</td>" +
      "<td>" + escapeHtml(pkg.type || "") + "</td>" +
      "<td>" + escapeHtml(vulnId) + "</td>" +
      "<td><span class='severity-pill " + severityClass(severity) + "'>" + escapeHtml(severity) + "</span></td>" +
      "<td>" + escapeHtml(fixedVer) + "</td>";
    tableBody.appendChild(row);
  }
}

function renderDependencyTree(tree) {
  dependencyTreeEl.innerHTML = "";

  if (!tree || tree.length === 0) {
    dependencyTreeEl.innerHTML = "<p>No dependency tree data available.</p>";
    return;
  }

  function buildTree(nodes) {
    const ul = document.createElement("ul");

    for (let i = 0; i < nodes.length; i++) {
      const li = document.createElement("li");
      li.textContent = nodes[i].name || "unknown";

      if (nodes[i].children && nodes[i].children.length) {
        li.appendChild(buildTree(nodes[i].children));
      }

      ul.appendChild(li);
    }

    return ul;
  }

  dependencyTreeEl.appendChild(buildTree(tree));
}

function renderPopulationSummary(rows) {
  const safeRows = rows || [];
  const activeCount = safeRows.filter(function(r) {
    return String(r.active) === "1";
  }).length;
  const inactiveCount = safeRows.length - activeCount;

  const sourceCounts = {};
  const typeCounts = {};

  safeRows.forEach(function(r) {
    const source = String(r.source_name || "unknown").trim() || "unknown";
    const type = String(r.target_type || "unknown").trim() || "unknown";
    sourceCounts[source] = (sourceCounts[source] || 0) + 1;
    typeCounts[type] = (typeCounts[type] || 0) + 1;
  });

  if (summaryActiveCount) summaryActiveCount.textContent = activeCount;
  if (summaryInactiveCount) summaryInactiveCount.textContent = inactiveCount;
  if (summarySourceCount) summarySourceCount.textContent = Object.keys(sourceCounts).length;
  if (summaryTypeCount) summaryTypeCount.textContent = Object.keys(typeCounts).length;

  function renderRankedList(container, entries, emptyMessage) {
    if (!container) return;

    container.innerHTML = "";

    if (!entries.length) {
      container.innerHTML = "<div class='muted'>" + emptyMessage + "</div>";
      return;
    }

    const topEntries = entries.slice(0, 5);

    topEntries.forEach(function(entry) {
      const item = document.createElement("div");
      item.className = "summary-row";

      const label = document.createElement("span");
      label.className = "summary-row-label";
      label.textContent = entry[0];

      const value = document.createElement("span");
      value.className = "summary-row-value";
      value.textContent = entry[1];

      item.appendChild(label);
      item.appendChild(value);
      container.appendChild(item);
    });

    if (entries.length > 5) {
      const more = document.createElement("div");
      more.className = "summary-more";
      more.textContent = "+" + (entries.length - 5) + " more";
      container.appendChild(more);
    }
  }

  const sourceEntries = Object.entries(sourceCounts).sort(function(a, b) {
    return b[1] - a[1];
  });

  const typeEntries = Object.entries(typeCounts).sort(function(a, b) {
    return b[1] - a[1];
  });

  renderRankedList(summaryBySource, sourceEntries, "No source data");
  renderRankedList(summaryByType, typeEntries, "No type data");
}

function renderImportHistory() {
  if (!importHistoryTableBody || !importHistoryShell || !importHistoryEmpty) return;

  importHistoryTableBody.innerHTML = "";

  if (!window._importHistory.length) {
    importHistoryShell.classList.add("hidden-panel");
    importHistoryEmpty.classList.remove("hidden-panel");
    return;
  }

  importHistoryShell.classList.remove("hidden-panel");
  importHistoryEmpty.classList.add("hidden-panel");

  window._importHistory.forEach(function(item) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHtml(item.time) + "</td>" +
      "<td>" + escapeHtml(item.mode) + "</td>" +
      "<td>" + escapeHtml(item.received) + "</td>" +
      "<td>" + escapeHtml(item.inserted) + "</td>" +
      "<td>" + escapeHtml(item.skipped_duplicates) + "</td>";
    importHistoryTableBody.appendChild(tr);
  });
}

function addImportHistoryEntry(mode, data) {
  const entry = {
    time: new Date().toLocaleString(),
    mode: mode,
    received: data.received || 0,
    inserted: data.inserted || 0,
    skipped_duplicates: data.skipped_duplicates || 0
  };

  window._importHistory.unshift(entry);
  window._importHistory = window._importHistory.slice(0, 10);
  renderImportHistory();
}

function renderDataset(rows) {
  datasetTableBody.innerHTML = "";

  if (!rows || rows.length === 0) {
    datasetTableBody.innerHTML = "<tr><td colspan='7'>No target rows found.</td></tr>";
    renderPopulationSummary([]);
    return;
  }

  renderPopulationSummary(rows);

  const searchText = (targetSearchInput ? targetSearchInput.value : "").trim().toLowerCase();
  const filterValue = targetFilterSelect ? targetFilterSelect.value : "all";

  const filtered = rows.filter(function(r) {
    const isActive = String(r.active) === "1";

    if (filterValue === "active" && !isActive) return false;
    if (filterValue === "inactive" && isActive) return false;

    const combined = [
      r.target_id,
      r.target_type,
      r.source_name,
      r.notes
    ].join(" ").toLowerCase();

    if (searchText && !combined.includes(searchText)) return false;

    return true;
  });

  if (filtered.length === 0) {
    datasetTableBody.innerHTML = "<tr><td colspan='7'>No matching targets found.</td></tr>";
    return;
  }

  filtered.forEach(function(r) {
    const tr = document.createElement("tr");
    const isActive = String(r.active) === "1";

    tr.innerHTML =
      "<td>" + escapeHtml(r.target_id || "") + "</td>" +
      "<td>" + escapeHtml(r.target_type || "") + "</td>" +
      "<td>" + escapeHtml(r.source_name || "") + "</td>" +
      "<td>" + getTargetStatusBadge(r.active) + "</td>" +
      "<td>" + formatDateTime(r.last_scan_time) + "</td>" +
      "<td>" + escapeHtml(r.notes || "") + "</td>" +
      "<td>" +
        "<div class='table-action-group'>" +
          "<button class='btn btn-small js-scan-target' data-target-pk='" + escapeHtml(r.target_pk) + "' data-target-id='" + escapeHtml(r.target_id) + "'>" +
            "Scan" +
          "</button>" +
          "<button class='btn btn-small js-toggle-status' data-target-pk='" + escapeHtml(r.target_pk) + "' data-next-active='" + (!isActive) + "'>" +
            (isActive ? "Disable" : "Enable") +
          "</button>" +
          "<button class='btn btn-small btn-danger js-delete-target' data-target-pk='" + escapeHtml(r.target_pk) + "'>" +
            "Delete" +
          "</button>" +
        "</div>" +
      "</td>";

    datasetTableBody.appendChild(tr);
  });

  bindTargetActionButtons();
}

function renderMonitorRowsToTable(rows, tbodyEl) {
  if (!tbodyEl) return;

  tbodyEl.innerHTML = "";

  if (!rows || rows.length === 0) {
    tbodyEl.innerHTML = "<tr><td colspan='10'>No monitor log rows found.</td></tr>";
    return;
  }

  rows.forEach(function(r) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + formatDateTime(r.scan_time) + "</td>" +
      "<td>" + escapeHtml(r.target_id || "") + "</td>" +
      "<td>" + escapeHtml(r.new_found ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.resolved ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.total_vulns ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.critical ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.high ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.medium ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.low ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.latest_scan_id ?? "") + "</td>";

    tbodyEl.appendChild(tr);
  });
}

function renderLatestScans(rows) {
  [latestScanTableBody, historyScanTableBody].forEach(function(tbody) {
    if (!tbody) return;

    tbody.innerHTML = "";

    if (!rows || rows.length === 0) {
      tbody.innerHTML = "<tr><td colspan='3'>No scan rows found.</td></tr>";
      return;
    }

    rows.forEach(function(r) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + escapeHtml(r.scan_id || "") + "</td>" +
        "<td>" + escapeHtml(r.target_id || "") + "</td>" +
        "<td>" + formatDateTime(r.scan_time) + "</td>";
      tbody.appendChild(tr);
    });
  });
}

function updateDashboard(datasetRows, monitorRows) {
  const safeDatasetRows = datasetRows || [];
  const safeMonitorRows = monitorRows || [];

  const activeCount = safeDatasetRows.filter(function(r) {
    return String(r.active) === "1";
  }).length;

  const inactiveCount = safeDatasetRows.length - activeCount;

  // Count each target once, using its most recent monitor row.
  // Rows arrive newest first, so the first row seen for a target is its latest.
  let totalVulns = 0;
  const countedTargets = {};
  safeMonitorRows.forEach(function(r) {
    const key = String(r.target_id || "");
    if (countedTargets[key]) return;
    countedTargets[key] = true;
    totalVulns += parseInt(r.total_vulns || 0, 10);
  });

  if (dashTotalTargets) dashTotalTargets.textContent = safeDatasetRows.length;
  if (dashActiveTargets) dashActiveTargets.textContent = activeCount;
  if (dashTotalScans) dashTotalScans.textContent = safeMonitorRows.length;
  if (dashTotalVulns) dashTotalVulns.textContent = totalVulns;

  if (healthActiveCount) healthActiveCount.textContent = activeCount;
  if (healthInactiveCount) healthInactiveCount.textContent = inactiveCount;
  if (healthMonitorCount) healthMonitorCount.textContent = safeMonitorRows.length;
}

function setLoading(isLoading, message) {
  const button = document.getElementById("scan-button");
  if (button) {
    button.disabled = isLoading;
    button.textContent = isLoading ? "Scanning..." : "Run Scan";
  }

  if (statusEl) {
    statusEl.innerHTML = escapeHtml(message || "");
  }
}

function setPopulationActionStatus(message) {
  if (populationActionStatus) {
    populationActionStatus.textContent = message || "";
  }
}

function setAnalyticsStatus(message) {
  if (analyticsStatus) {
    analyticsStatus.textContent = message || "";
  }
}

function reloadAnalyticsFrame() {
  if (analyticsFrame) {
    analyticsFrame.src = "/static/dashboard_plus/dashboard_plus.html?v=" + Date.now();
  }
}

function refreshAnalytics() {
  setAnalyticsStatus("Refreshing analytics in background... please wait a little.");

  fetch("/api/analytics/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
    .then(function(res) {
      return res.json().then(function(data) {
        if (!res.ok) throw new Error(data.error || "Analytics refresh failed");
        return data;
      });
    })
    .then(function(data) {
      setAnalyticsStatus((data.message || "Analytics refresh started.") + " Reload the analytics view after 10-20 seconds.");
    })
    .catch(function(err) {
      console.error(err);
      setAnalyticsStatus("Error refreshing analytics: " + err.message);
    });
}

function fetchDataset() {
  return fetch("/api/db/targets")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load targets");
      return res.json();
    })
    .then(function(data) {
      window._datasetRows = data.rows || [];
      renderDataset(window._datasetRows);
      updateDashboard(window._datasetRows, window._monitorRows);
      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
      markConnectionLost();
    });
}

function fetchLatestScans() {
  return fetch("/api/db/latest-scans")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load latest scans");
      return res.json();
    })
    .then(function(data) {
      window._latestScanRows = data.rows || [];
      renderLatestScans(window._latestScanRows);
      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
      markConnectionLost();
    });
}

function fetchMonitorLog() {
  if (monitorStatusEl) {
    monitorStatusEl.textContent = "Loading monitoring data...";
  }

  return fetch("/api/db/monitor-log")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load monitor log");
      return res.json();
    })
    .then(function(data) {
      window._monitorRows = data.rows || [];
      renderMonitorRowsToTable(window._monitorRows, monitorTableBody);
      renderMonitorRowsToTable(window._monitorRows, historyMonitorTableBody);
      updateDashboard(window._datasetRows, window._monitorRows);

      if (monitorStatusEl) {
        monitorStatusEl.textContent = "";
      }

      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
      markConnectionLost();
      if (monitorStatusEl) {
        monitorStatusEl.textContent = "Error loading monitoring data.";
      }
    });
}

function bindTargetActionButtons() {
  document.querySelectorAll(".js-scan-target").forEach(function(btn) {
    btn.addEventListener("click", function() {
      const targetPk = this.getAttribute("data-target-pk");
      const targetId = this.getAttribute("data-target-id") || "";

      setPopulationActionStatus("Scanning target: " + targetId + " ...");

      fetch("/api/db/targets/" + targetPk + "/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          useCache: true,
          shallowClone: true
        })
      })
        .then(function(res) {
          return res.json().then(function(data) {
            if (!res.ok) throw new Error(data.error || "Scan failed");
            return data;
          });
        })
        .then(function(data) {
          if (!data.report) {
            throw new Error("No report data received");
          }

          renderSummary(data.report);
          renderTable(data.report.packages || []);
          renderDependencyTree(data.report.dependency_tree || []);

          setPopulationActionStatus("Scan completed for: " + targetId + ". Analytics refresh started in background.");
          switchPanel("results-panel");

          fetchDataset();
          fetchLatestScans();
          fetchMonitorLog();
        })
        .catch(function(err) {
          console.error(err);
          setPopulationActionStatus("Error scanning target: " + err.message);
          alert("Scan failed: " + err.message);
        });
    });
  });

  document.querySelectorAll(".js-toggle-status").forEach(function(btn) {
    btn.addEventListener("click", function() {
      const targetPk = this.getAttribute("data-target-pk");
      const nextActive = this.getAttribute("data-next-active") === "true";

      fetch("/api/db/targets/" + targetPk + "/status", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active: nextActive })
      })
        .then(function(res) {
          if (!res.ok) throw new Error("Failed to update target status");
          return res.json();
        })
        .then(function() {
          fetchDataset();
        })
        .catch(function(err) {
          console.error(err);
          alert("Could not update target status.");
        });
    });
  });

  document.querySelectorAll(".js-delete-target").forEach(function(btn) {
    btn.addEventListener("click", function() {
      const targetPk = this.getAttribute("data-target-pk");

      if (!confirm("Delete this target from initial population?")) {
        return;
      }

      fetch("/api/db/targets/" + targetPk, {
        method: "DELETE"
      })
        .then(function(res) {
          if (!res.ok) throw new Error("Failed to delete target");
          return res.json();
        })
        .then(function() {
          fetchDataset();
        })
        .catch(function(err) {
          console.error(err);
          alert("Could not delete target.");
        });
    });
  });
}

function setupAddTargetForm() {
  if (!addTargetForm) return;

  addTargetForm.addEventListener("submit", function(event) {
    event.preventDefault();

    const payload = {
      target_id: document.getElementById("new-target-id").value.trim(),
      target_type: document.getElementById("new-target-type").value.trim(),
      source_name: document.getElementById("new-source-name").value.trim(),
      notes: document.getElementById("new-notes").value.trim(),
      active: document.getElementById("new-active").checked
    };

    addTargetStatus.textContent = "Adding target...";

    fetch("/api/db/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function(res) {
        return res.json().then(function(data) {
          if (!res.ok) {
            throw new Error(data.error || "Failed to add target");
          }
          return data;
        });
      })
      .then(function(data) {
        addTargetStatus.textContent = data.message || "Target added successfully.";
        addTargetForm.reset();
        document.getElementById("new-active").checked = true;
        fetchDataset();
        switchPanel("population-panel");
      })
      .catch(function(err) {
        console.error(err);
        addTargetStatus.textContent = "Error: " + err.message;
      });
  });
}

function setupImportForms() {
  if (importFileForm) {
    importFileForm.addEventListener("submit", function(event) {
      event.preventDefault();

      const file = importFileInput.files && importFileInput.files[0];
      if (!file) {
        importStatus.textContent = "Please choose a CSV or JSON file.";
        return;
      }

      const formData = new FormData();
      formData.append("file", file);

      importStatus.textContent = "Importing file...";

      fetch("/api/db/targets/import", {
        method: "POST",
        body: formData
      })
        .then(function(res) {
          return res.json().then(function(data) {
            if (!res.ok) {
              const details = data.details ? "\n" + data.details.join("\n") : "";
              throw new Error((data.error || "Import failed") + details);
            }
            return data;
          });
        })
        .then(function(data) {
          importStatus.textContent =
            "Import completed.\n" +
            "Received: " + (data.received || 0) + "\n" +
            "Inserted: " + (data.inserted || 0) + "\n" +
            "Skipped duplicates: " + (data.skipped_duplicates || 0);

          addImportHistoryEntry("File Upload", data);
          importFileForm.reset();
          fetchDataset();
          switchPanel("population-panel");
        })
        .catch(function(err) {
          console.error(err);
          importStatus.textContent = "Error: " + err.message;
        });
    });
  }

  if (importJsonTextForm) {
    importJsonTextForm.addEventListener("submit", function(event) {
      event.preventDefault();

      const rawText = importJsonText.value.trim();
      if (!rawText) {
        importStatus.textContent = "Please paste JSON content first.";
        return;
      }

      const formData = new FormData();
      formData.append("content_type", "json");
      formData.append("raw_text", rawText);

      importStatus.textContent = "Importing pasted JSON...";

      fetch("/api/db/targets/import", {
        method: "POST",
        body: formData
      })
        .then(function(res) {
          return res.json().then(function(data) {
            if (!res.ok) {
              const details = data.details ? "\n" + data.details.join("\n") : "";
              throw new Error((data.error || "Import failed") + details);
            }
            return data;
          });
        })
        .then(function(data) {
          importStatus.textContent =
            "Import completed.\n" +
            "Received: " + (data.received || 0) + "\n" +
            "Inserted: " + (data.inserted || 0) + "\n" +
            "Skipped duplicates: " + (data.skipped_duplicates || 0);

          addImportHistoryEntry("Pasted JSON", data);
          importJsonTextForm.reset();
          fetchDataset();
          switchPanel("population-panel");
        })
        .catch(function(err) {
          console.error(err);
          importStatus.textContent = "Error: " + err.message;
        });
    });
  }
}

function setupTargetFilters() {
  if (targetSearchInput) {
    targetSearchInput.addEventListener("input", function() {
      renderDataset(window._datasetRows);
    });
  }

  if (targetFilterSelect) {
    targetFilterSelect.addEventListener("change", function() {
      renderDataset(window._datasetRows);
    });
  }
}

function setupScanAllActiveButton() {
  if (!scanAllActiveBtn) return;

  scanAllActiveBtn.addEventListener("click", function() {
    if (!confirm("Run scan for all active targets? Start with a small set first.")) {
      return;
    }

    setPopulationActionStatus("Scanning all active targets...");

    scanAllActiveBtn.disabled = true;
    scanAllActiveBtn.textContent = "Scanning...";

    fetch("/api/db/targets/scan-all-active", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        useCache: true,
        shallowClone: true
      })
    })
      .then(function(res) {
        return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Scan all failed");
          return data;
        });
      })
      .then(function(data) {
        setPopulationActionStatus(
          "Scan-all completed. Success: " +
          (data.success_count || 0) +
          ", Failed: " +
          (data.failed_count || 0) +
          ". Analytics refresh started in background."
        );

        fetchDataset();
        fetchLatestScans();
        fetchMonitorLog();

        if (data.results && data.results.length > 0) {
          const firstSuccess = data.results.find(function(item) {
            return item.status === "success";
          });
          if (firstSuccess) {
            switchPanel("history-panel");
          }
        }
      })
      .catch(function(err) {
        console.error(err);
        setPopulationActionStatus("Error scanning active targets: " + err.message);
        alert("Scan-all failed: " + err.message);
      })
      .finally(function() {
        scanAllActiveBtn.disabled = false;
        scanAllActiveBtn.textContent = "Scan All Active Targets";
      });
  });
}

function setupAnalyticsControls() {
  if (refreshAnalyticsBtn) {
    refreshAnalyticsBtn.addEventListener("click", refreshAnalytics);
  }

  if (reloadAnalyticsFrameBtn) {
    reloadAnalyticsFrameBtn.addEventListener("click", reloadAnalyticsFrame);
  }
}

function setupForm() {
  if (!form) return;

  form.addEventListener("submit", function(event) {
    event.preventDefault();

    const target = targetInput.value.trim();
    if (!target) {
      setLoading(false, "Please enter a repository URL or local path.");
      return;
    }

    setLoading(true, "Preparing scan...");

    const payload = {
      target: target,
      useCache: useCacheInput.checked,
      shallowClone: shallowCloneInput.checked,
      skipVuln: false
    };

    const startTime = Date.now();

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function(response) {
        if (!response.ok) {
          return response.json().then(function(err) {
            throw new Error(err.error || "Scan failed");
          });
        }
        return response.json();
      })
      .then(function(data) {
        if (!data.report) {
          throw new Error("No report data received");
        }

        renderSummary(data.report);
        renderTable(data.report.packages || []);
        renderDependencyTree(data.report.dependency_tree || []);

        const totalTime = Math.floor((Date.now() - startTime) / 1000);
        setLoading(false, "Scan completed successfully in " + totalTime + "s. Analytics refresh started in background.");

        switchPanel("results-panel");
        fetchLatestScans();
        fetchMonitorLog();
      })
      .catch(function(error) {
        console.error(error);
        setLoading(false, "Error: " + error.message);
      });
  });
}

function initApp() {
  initElements();
  setupSidebarNavigation();
  setupForm();
  setupAddTargetForm();
  setupImportForms();
  setupTargetFilters();
  setupScanAllActiveButton();
  setupAnalyticsControls();

  renderImportHistory();
  fetchDataset();
  fetchMonitorLog();
  fetchLatestScans();

  if (refreshMonitorBtn) {
    refreshMonitorBtn.addEventListener("click", fetchMonitorLog);
  }

  if (refreshDatasetBtn) {
    refreshDatasetBtn.addEventListener("click", fetchDataset);
  }

  setInterval(fetchDataset, 120000);
  setInterval(fetchMonitorLog, 120000);
  setInterval(fetchLatestScans, 120000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}