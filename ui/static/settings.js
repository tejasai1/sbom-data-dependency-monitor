// Settings panel: auto-scan interval (more settings can be added here later).
// Also keeps the sidebar "Auto monitoring" card in sync with the saved value.
// Kept separate from app.js so the existing dashboard code is untouched.
(function () {
  "use strict";

  const el = (id) => document.getElementById(id);

  async function requestJson(url, options) {
    const response = await fetch(url, options);
    let data = {};
    try {
      data = await response.json();
    } catch (err) {
      data = {};
    }
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
  }

  function setStatus(message, kind) {
    const box = el("settings-autoscan-status");
    if (!box) return;
    box.textContent = message;
    box.classList.toggle("dep-error", kind === "error");
  }

  function formatTime(iso) {
    if (!iso) return "Not yet";
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
  }

  function shortName(id) {
    return String(id || "").replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/\/$/, "");
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Progress box under the three cards; created here so index.html needs no change.
  function progressBox() {
    let box = el("settings-progress");
    if (!box) {
      const grid = el("settings-next-scan")?.closest(".summary-stat-grid");
      if (!grid) return null;
      box = document.createElement("div");
      box.id = "settings-progress";
      box.className = "status-box";
      box.style.marginTop = "16px";
      box.style.whiteSpace = "normal";
      grid.insertAdjacentElement("afterend", box);
    }
    return box;
  }

  function renderProgress(autoScan) {
    const box = progressBox();
    if (!box) return;

    const p = autoScan.progress;
    if (autoScan.running && p) {
      const pct = p.total ? Math.round((p.done / p.total) * 100) : 0;
      const counts = [`${p.succeeded} succeeded`, `${p.failed} failed`]
        .concat(p.skipped ? [`${p.skipped} skipped`] : [])
        .join(", ");
      box.innerHTML = `
        <strong>${p.total ? `Auto scan running: ${p.done} of ${p.total} targets (${pct}%)` : "Auto scan starting: loading the list of active targets..."}</strong>
        <div style="height:10px;margin:10px 0;border-radius:6px;background:#e3e8ef;overflow:hidden"
             role="progressbar" aria-valuemin="0" aria-valuemax="${p.total}" aria-valuenow="${p.done}">
          <div style="height:100%;width:${pct}%;min-width:8px;background:#2563eb;transition:width .4s"></div>
        </div>
        ${p.current ? `<div>Now scanning: <strong title="${escapeHtml(p.current)}">${escapeHtml(shortName(p.current))}</strong></div>` : ""}
        <div class="muted">Started ${escapeHtml(formatTime(autoScan.running_since))}. So far: ${counts}.</div>`;
      box.style.display = "";
      return;
    }

    const last = autoScan.last_cycle;
    if (last) {
      const counts = [`${last.succeeded} succeeded`, `${last.failed} failed`]
        .concat(last.skipped ? [`${last.skipped} skipped`] : [])
        .join(", ");
      box.innerHTML = `<strong>Last cycle:</strong> ${last.total} targets, ${counts}. ` +
        `<span class="muted">Ran ${escapeHtml(formatTime(last.started))} to ${escapeHtml(formatTime(last.finished))}.</span>`;
      box.style.display = "";
    } else {
      box.style.display = "none";
    }
  }

  function renderSettings(autoScan) {
    // sidebar card, visible on every page
    const sidebar = el("sidebar-scan-interval");
    if (sidebar) sidebar.textContent = `Every ${autoScan.interval_label}`;

    const select = el("settings-autoscan-interval");
    if (!select) return;

    // don't overwrite a choice the user is in the middle of making
    const userIsEditing = select.dataset.dirty === "true";
    select.innerHTML = autoScan.options
      .map((o) => `<option value="${o.minutes}">${o.label}</option>`)
      .join("");
    select.value = userIsEditing ? select.dataset.pending : String(autoScan.interval_minutes);

    el("settings-current-interval").textContent = autoScan.interval_label;
    el("settings-last-scan").textContent = formatTime(autoScan.last_completed);

    let next;
    if (autoScan.running) {
      next = "After the current cycle finishes";
    } else if (!autoScan.next_due) {
      next = "Within a minute";
    } else if (new Date(autoScan.next_due) <= new Date()) {
      next = "Due now (starts within a minute)";
    } else {
      next = formatTime(autoScan.next_due);
    }
    el("settings-next-scan").textContent = next;

    renderProgress(autoScan);
  }

  let refreshTimer = null;

  async function loadSettings() {
    let running = false;
    try {
      const data = await requestJson("/api/settings");
      renderSettings(data.auto_scan);
      running = data.auto_scan.running;
    } catch (err) {
      setStatus(`Could not load settings: ${err.message}`, "error");
    }
    // refresh every 5 seconds while a cycle runs, otherwise once a minute
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(loadSettings, running ? 5000 : 60000);
  }

  async function saveAutoScan(event) {
    event.preventDefault();
    const select = el("settings-autoscan-interval");
    const button = el("settings-autoscan-form").querySelector('button[type="submit"]');
    button.disabled = true;
    setStatus("Saving...");

    try {
      const data = await requestJson("/api/settings/auto-scan", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ interval_minutes: Number(select.value) }),
      });
      select.dataset.dirty = "false";
      setStatus(`${data.message} The change applies within about a minute; no restart needed.`);
      await loadSettings();
    } catch (err) {
      setStatus(`Could not save: ${err.message}`, "error");
    } finally {
      button.disabled = false;
    }
  }

  function init() {
    // the sidebar text is updated even if the Settings panel isn't open
    loadSettings();

    const form = el("settings-autoscan-form");
    if (!form) return;

    form.addEventListener("submit", saveAutoScan);
    el("settings-autoscan-interval").addEventListener("change", (event) => {
      event.target.dataset.dirty = "true";
      event.target.dataset.pending = event.target.value;
    });

    const navButton = document.querySelector('.nav-item[data-panel="settings-panel"]');
    if (navButton) navButton.addEventListener("click", loadSettings);

  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
