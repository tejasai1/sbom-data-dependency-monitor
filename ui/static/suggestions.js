// Suggested data flows (Phase 2, FlowTrace discovery).
// Follows the repository selected in the Data Dependencies tab. "Find flows in code"
// asks the server to read that repository's code with the model; each suggestion is
// shown with its code evidence and is only recorded when a manager approves it.
(function () {
  "use strict";

  const el = (id) => document.getElementById(id);

  let currentPk = null;
  let rows = [];       // all pending suggestions
  let requestId = 0;   // ignores answers for a repository the user has moved away from

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Same short names as the rest of the tab: owner/repo, or the last two folders of a path
  function shortName(targetId) {
    const full = String(targetId ?? "");
    if (/github\.com\//i.test(full)) {
      return full.replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/\/$/, "");
    }
    const parts = full.split(/[\\/]+/).filter(Boolean);
    return parts.length >= 2 ? parts.slice(-2).join("/") : full;
  }

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
    const box = el("sug-status");
    box.textContent = message;
    box.classList.toggle("sug-error", kind === "error");
    box.classList.toggle("sug-pending", kind === "pending");
  }

  // ---------- list ----------
  async function loadSuggestions() {
    try {
      const data = await requestJson("/api/discovery/suggestions");
      rows = data.rows || [];
      render();
    } catch (err) {
      setStatus(`Could not load suggestions: ${err.message}`, "error");
    }
  }

  function render() {
    if (currentPk === null) return;
    const mine = rows.filter((r) => r.source_target_pk === currentPk || r.dest_target_pk === currentPk);
    el("sug-total").textContent = `(${rows.length} pending in total.)`;
    el("sug-list").innerHTML = mine.length
      ? mine.map(suggestionHtml).join("")
      : '<li class="muted sug-none">No pending suggestions for this repository.</li>';
  }

  function suggestionHtml(r) {
    const items = (r.items || []).join(", ");
    const evidence = (r.evidence || [])
      .map(
        (e) => `
        <div class="sug-ev">
          <div class="sug-ev-file">${escapeHtml(e.file)}, lines ${e.start_line}-${e.end_line}</div>
          <pre>${escapeHtml(e.snippet)}</pre>
        </div>`
      )
      .join("");
    return `
      <li class="sug-item">
        <div class="sug-line">
          <strong>${escapeHtml(shortName(r.source_id))}</strong> sends data to
          <strong>${escapeHtml(shortName(r.dest_id))}</strong>
        </div>
        <div class="sug-data">${escapeHtml(r.data)}${items ? `: ${escapeHtml(items)}` : ""}</div>
        <div class="sug-meta">
          ${escapeHtml(r.category)} · ${escapeHtml(r.mechanism)} · ${escapeHtml(r.confidence)} confidence ·
          ${escapeHtml(r.reason)} · found in ${escapeHtml(shortName(r.found_in_id))}'s code
        </div>
        <details>
          <summary>Code evidence (${(r.evidence || []).length})</summary>
          ${evidence}
        </details>
        <div class="sug-actions">
          <button type="button" class="btn btn-primary btn-inline" data-id="${r.suggestion_id}" data-action="approve">Approve</button>
          <button type="button" class="btn btn-secondary" data-id="${r.suggestion_id}" data-action="reject">Reject</button>
        </div>
      </li>`;
  }

  // ---------- discovery ----------
  async function runDiscovery() {
    if (currentPk === null) return;
    const myRequest = ++requestId;
    const button = el("sug-run");
    button.disabled = true;
    setStatus("Reading the code with the model... this can take up to a minute.", "pending");
    try {
      const data = await requestJson("/api/discovery/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: currentPk }),
      });
      if (myRequest !== requestId) return;
      const skipped = (data.skipped || []).length;
      setStatus(
        `Read ${data.files} files and found ${(data.flows || []).length} flows. ` +
          `Saved ${data.saved ?? 0} new suggestion(s)` +
          (skipped ? `; ${skipped} skipped because they are already recorded or decided.` : ".")
      );
      await loadSuggestions();
    } catch (err) {
      if (myRequest !== requestId) return;
      setStatus(`Could not find flows: ${err.message}`, "error");
    } finally {
      if (myRequest === requestId) button.disabled = false;
    }
  }

  // ---------- approve / reject ----------
  async function decide(id, action, button) {
    button.disabled = true;
    try {
      await requestJson(`/api/discovery/suggestions/${id}/${action}`, { method: "POST" });
      setStatus(
        action === "approve"
          ? "Approved. The data dependency is now recorded."
          : "Rejected. It won't be suggested again."
      );
      await loadSuggestions();
      if (action === "approve") document.dispatchEvent(new CustomEvent("dep:changed"));
    } catch (err) {
      setStatus(`Could not ${action}: ${err.message}`, "error");
      button.disabled = false;
    }
  }

  // ---------- wiring ----------
  function init() {
    if (!el("sug-card")) return;

    document.addEventListener("dep:selected", (event) => {
      currentPk = event.detail.pk;
      requestId += 1;
      el("sug-empty").classList.add("hidden-panel");
      el("sug-body").classList.remove("hidden-panel");
      el("sug-run").disabled = false;
      setStatus("Click \"Find flows in code\" to analyze this repository's code.");
      loadSuggestions();
    });

    el("sug-run").addEventListener("click", runDiscovery);

    el("sug-list").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-action]");
      if (button) decide(Number(button.dataset.id), button.dataset.action, button);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
