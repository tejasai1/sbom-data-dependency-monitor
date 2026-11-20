// Code evidence panel: shows the code that proves a data flow between two systems.
// Used by the Data Flow Tree (dependencies.js) and the impact tree (impact.js).
// Evidence exists for links found by FlowTrace and approved by a manager; links a
// manager typed in by hand have none, and the panel says so.
(function () {
  "use strict";

  let panel = null;
  let requestId = 0;

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function build() {
    panel = document.createElement("div");
    panel.id = "ev-panel";
    panel.className = "ev-panel hidden-panel";
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-labelledby", "ev-title");
    panel.innerHTML = `
      <div class="ev-head">
        <h4 id="ev-title"></h4>
        <button type="button" class="ev-close" aria-label="Close">&times;</button>
      </div>
      <div id="ev-body" class="ev-body"></div>`;
    document.body.appendChild(panel);
    panel.querySelector(".ev-close").addEventListener("click", hide);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") hide();
    });
  }

  function hide() {
    if (panel) panel.classList.add("hidden-panel");
  }

  function formatDate(value) {
    const d = new Date(value);
    return isNaN(d) ? String(value ?? "") : d.toLocaleDateString();
  }

  function rowHtml(r) {
    const items = (r.items || []).join(", ");
    const evidence = (r.evidence || [])
      .map(
        (e) => `
        <div class="ev-snippet">
          <div class="ev-file">${escapeHtml(e.file)}, lines ${e.start_line}-${e.end_line}</div>
          <pre>${escapeHtml(e.snippet)}</pre>
        </div>`
      )
      .join("");
    return `
      <p class="ev-data"><strong>${escapeHtml(r.data)}</strong>${items ? `: ${escapeHtml(items)}` : ""}</p>
      <p class="ev-meta">${escapeHtml(r.category)} · ${escapeHtml(r.mechanism)} · ${escapeHtml(r.confidence)} confidence · ${escapeHtml(r.reason)}</p>
      <p class="ev-meta">Found by FlowTrace in ${escapeHtml(r.found_in)}'s code and approved on ${escapeHtml(formatDate(r.decided_at))}.</p>
      ${evidence || '<p class="muted">No code lines were stored for this link.</p>'}
      <p class="ev-note">The code shown is copied from the real files, not from the model.</p>`;
  }

  function manualHtml() {
    return `
      <p>This link was <strong>recorded manually</strong> by a manager, so there is no code evidence.</p>
      <p class="muted">Links found with "Find flows in code" and approved show the code that proves them.</p>`;
  }

  async function show(source, destination) {
    if (!panel) build();
    const myRequest = ++requestId;
    panel.classList.remove("hidden-panel");
    panel.querySelector("#ev-title").textContent = `${source} sends data to ${destination}`;
    const body = panel.querySelector("#ev-body");
    body.innerHTML = '<p class="muted">Loading the code evidence...</p>';
    try {
      const response = await fetch("/api/discovery/evidence");
      let data = {};
      try {
        data = await response.json();
      } catch (err) {
        data = {};
      }
      if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
      if (myRequest !== requestId) return;
      const row = (data.rows || []).find((r) => r.source === source && r.destination === destination);
      body.innerHTML = row ? rowHtml(row) : manualHtml();
    } catch (err) {
      if (myRequest !== requestId) return;
      body.innerHTML = `<p class="ev-error">Could not load the evidence: ${escapeHtml(err.message)}</p>`;
    }
  }

  window.EvidencePanel = { show, hide };
})();
