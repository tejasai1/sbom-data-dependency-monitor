// Data Dependencies panel.
// Workflow: pick a repository, tick the repositories it gets data from, save,
// then review the result as a tree (upstream and downstream).
// Kept separate from app.js so the existing dashboard code is untouched.
(function () {
  "use strict";

  const MAX_TREE_DEPTH = 10;
  const el = (id) => document.getElementById(id);

  // ---------- state ----------
  let repos = [];                 // [{target_pk, target_id}]
  let nameByPk = new Map();       // target_pk -> target_id
  let sourcesOf = new Map();      // repo -> Set(repos it gets data from)
  let targetsOf = new Map();      // repo -> Set(repos it sends data to)
  let selectedPk = null;
  let pendingSources = new Set(); // ticked in the editor, not saved yet
  let editedByUser = false;       // true only after the user ticks or unticks something

  // ---------- helpers ----------
  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // "https://github.com/owner/repo" -> "owner/repo"; "C:\...\robot-shop\cart" -> "robot-shop/cart"
  function shortName(pk) {
    const full = String(nameByPk.get(pk) ?? `#${pk}`);
    if (/github\.com\//i.test(full)) {
      return full.replace(/^https?:\/\/(www\.)?github\.com\//i, "").replace(/\/$/, "");
    }
    const parts = full.split(/[\\/]+/).filter(Boolean);
    return parts.length >= 2 ? parts.slice(-2).join("/") : full;
  }

  function fullName(pk) {
    return nameByPk.get(pk) ?? `#${pk}`;
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
    const box = el("dep-save-status");
    box.textContent = message;
    box.classList.toggle("dep-error", kind === "error");
    box.classList.toggle("dep-pending", kind === "pending");
  }

  function sameSet(a, b) {
    if (a.size !== b.size) return false;
    for (const v of a) if (!b.has(v)) return false;
    return true;
  }

  function savedSources() {
    return sourcesOf.get(selectedPk) || new Set();
  }

  function hasUnsavedChanges() {
    return selectedPk !== null && !sameSet(pendingSources, savedSources());
  }

  // ---------- loading ----------
  async function loadAll() {
    el("dep-repo-count").textContent = "Loading repositories...";
    try {
      const [targets, deps] = await Promise.all([
        requestJson("/api/db/targets"),
        requestJson("/api/dependencies"),
      ]);

      repos = (targets.rows || []).map((r) => ({ target_pk: r.target_pk, target_id: r.target_id }));
      nameByPk = new Map(repos.map((r) => [r.target_pk, r.target_id]));

      sourcesOf = new Map();
      targetsOf = new Map();
      for (const d of deps.rows || []) {
        if (!sourcesOf.has(d.dest_target_pk)) sourcesOf.set(d.dest_target_pk, new Set());
        if (!targetsOf.has(d.source_target_pk)) targetsOf.set(d.source_target_pk, new Set());
        sourcesOf.get(d.dest_target_pk).add(d.source_target_pk);
        targetsOf.get(d.source_target_pk).add(d.dest_target_pk);
      }
    } catch (err) {
      el("dep-repo-count").textContent = `Could not load repositories: ${err.message}`;
      el("dep-repo-count").classList.add("dep-error");
      return;
    }
    el("dep-repo-count").classList.remove("dep-error");

    renderRepoList();
    if (selectedPk !== null && nameByPk.has(selectedPk)) {
      if (!editedByUser) pendingSources = new Set(savedSources());
      renderEditor();
      renderTrees();
    }
  }

  // ---------- Step 1: repository list ----------
  function renderRepoList() {
    const query = el("dep-repo-search").value.trim().toLowerCase();
    const onlyLinked = el("dep-only-linked").checked;

    const visible = repos
      .filter((r) => !query || String(r.target_id).toLowerCase().includes(query))
      .filter((r) => !onlyLinked || sourcesOf.has(r.target_pk) || targetsOf.has(r.target_pk))
      .sort((a, b) => shortName(a.target_pk).localeCompare(shortName(b.target_pk)));

    el("dep-repo-count").textContent = `${visible.length} of ${repos.length} repositories`;

    el("dep-repo-list").innerHTML = visible.length
      ? visible
          .map((r) => {
            const ins = (sourcesOf.get(r.target_pk) || new Set()).size;
            const outs = (targetsOf.get(r.target_pk) || new Set()).size;
            const badges = [
              ins ? `<span class="dep-badge">from ${ins}</span>` : "",
              outs ? `<span class="dep-badge">to ${outs}</span>` : "",
            ].join("");
            const selected = r.target_pk === selectedPk ? " dep-repo-selected" : "";
            return `
              <li>
                <button type="button" class="dep-repo-item${selected}" data-pk="${r.target_pk}"
                  title="${escapeHtml(r.target_id)}">
                  <span class="dep-repo-name">${escapeHtml(shortName(r.target_pk))}</span>
                  <span class="dep-badges">${badges}</span>
                </button>
              </li>`;
          })
          .join("")
      : '<li class="muted dep-list-empty">No repositories match.</li>';
  }

  function selectRepo(pk) {
    if (pk === selectedPk) return;
    if (hasUnsavedChanges() && !window.confirm("You have unsaved changes for this repository. Discard them?")) {
      return;
    }
    selectedPk = pk;
    pendingSources = new Set(savedSources());
    editedByUser = false;
    el("dep-source-search").value = "";
    setStatus("Tick every repository this one gets data from, then save.");

    el("dep-editor-empty").classList.add("hidden-panel");
    el("dep-editor").classList.remove("hidden-panel");
    el("dep-tree-empty").classList.add("hidden-panel");
    el("dep-tree").classList.remove("hidden-panel");

    renderRepoList();
    renderEditor();
    renderTrees();
    loadVulnSummary(pk);
    document.dispatchEvent(new CustomEvent("dep:selected", { detail: { pk, name: shortName(pk) } }));
  }

  // ---------- Step 2: "gets data from" editor ----------
  function renderEditor() {
    el("dep-editor-title").textContent = shortName(selectedPk);
    el("dep-editor-title").title = fullName(selectedPk);

    // chips for what is currently ticked
    const chips = [...pendingSources].sort((a, b) => shortName(a).localeCompare(shortName(b)));
    el("dep-chips").innerHTML = chips.length
      ? chips
          .map(
            (pk) => `
            <span class="dep-chip" title="${escapeHtml(fullName(pk))}">
              ${escapeHtml(shortName(pk))}
              <button type="button" class="dep-chip-remove" data-pk="${pk}"
                aria-label="Remove ${escapeHtml(shortName(pk))}">&times;</button>
            </span>`
          )
          .join("")
      : '<span class="muted">No sources yet. Tick repositories below.</span>';

    renderSourceList();

    const dirty = hasUnsavedChanges();
    el("dep-save").disabled = !dirty;
    el("dep-reset").disabled = !dirty;
    if (dirty) setStatus("You have unsaved changes.", "pending");
  }

  function renderSourceList() {
    const query = el("dep-source-search").value.trim().toLowerCase();
    const options = repos
      .filter((r) => r.target_pk !== selectedPk)
      .filter((r) => !query || String(r.target_id).toLowerCase().includes(query))
      .sort((a, b) => {
        // ticked ones first, then alphabetical
        const ta = pendingSources.has(a.target_pk) ? 0 : 1;
        const tb = pendingSources.has(b.target_pk) ? 0 : 1;
        return ta - tb || shortName(a.target_pk).localeCompare(shortName(b.target_pk));
      });

    el("dep-source-list").innerHTML = options.length
      ? options
          .map((r) => {
            const checked = pendingSources.has(r.target_pk) ? "checked" : "";
            return `
              <li>
                <label class="dep-source-option" title="${escapeHtml(r.target_id)}">
                  <input type="checkbox" value="${r.target_pk}" ${checked}>
                  <span>${escapeHtml(shortName(r.target_pk))}</span>
                </label>
              </li>`;
          })
          .join("")
      : '<li class="muted dep-list-empty">No repositories match.</li>';
  }

  function toggleSource(pk, on) {
    editedByUser = true;
    if (on) pendingSources.add(pk);
    else pendingSources.delete(pk);
    renderEditor();
  }

  async function saveSources() {
    const pk = selectedPk;
    const button = el("dep-save");
    button.disabled = true;
    setStatus("Saving...", "pending");

    try {
      const data = await requestJson(`/api/dependencies/sources/${pk}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source_target_pks: [...pendingSources] }),
      });
      await loadAll();
      pendingSources = new Set(savedSources());
      editedByUser = false;
      renderEditor();
      setStatus(
        `Saved. ${shortName(pk)} now gets data from ${data.total} ` +
          `repositor${data.total === 1 ? "y" : "ies"} (${data.added} added, ${data.removed} removed).`
      );
    } catch (err) {
      setStatus(`Could not save: ${err.message}`, "error");
      button.disabled = false;
    }
  }

  function resetSources() {
    pendingSources = new Set(savedSources());
    editedByUser = false;
    renderEditor();
    setStatus("Changes undone.");
  }

  // ---------- Step 3: trees ----------
  function renderTrees() {
    renderTree(el("dep-tree-upstream"), sourcesOf, "Nothing recorded yet. Use Step 2 to add sources.");
    renderTree(el("dep-tree-downstream"), targetsOf, "No repository gets data from this one yet.");
  }

  function renderTree(container, childrenOf, emptyText) {
    const kids = [...(childrenOf.get(selectedPk) || [])];
    if (!kids.length) {
      container.innerHTML = `<div class="muted">${escapeHtml(emptyText)}</div>`;
      return;
    }
    const shown = new Set([selectedPk]); // systems whose branch is already drawn
    // Shortest hop distance of every system from the selected repository
    const dist = new Map([[selectedPk, 0]]);
    let frontier = [selectedPk];
    while (frontier.length) {
      const next = [];
      for (const p of frontier) {
        for (const c of childrenOf.get(p) || []) {
          if (!dist.has(c)) {
            dist.set(c, dist.get(p) + 1);
            next.push(c);
          }
        }
      }
      frontier = next;
    }
    container.innerHTML = `
      <div class="dep-tree-root">${escapeHtml(shortName(selectedPk))}</div>
      <ul class="dep-tree">${sortPks(kids).map((k) => treeNode(k, childrenOf, [selectedPk], 1, shown, dist)).join("")}</ul>`;
  }
  function sortPks(pks) {
    return [...pks].sort((a, b) => shortName(a).localeCompare(shortName(b)));
  }

  function treeNode(pk, childrenOf, path, depth, shown, dist) {
    // The link drawn here: in the downstream tree the parent sends data to this system,
    // in the upstream tree this system sends data to the parent.
    const parent = path[path.length - 1];
    const [src, dst] = childrenOf === targetsOf ? [parent, pk] : [pk, parent];
    const label =
      `<button type="button" class="dep-node" data-pk="${pk}" title="${escapeHtml(fullName(pk))}">${escapeHtml(shortName(pk))}</button>` +
      `<button type="button" class="dep-ev" data-src="${src}" data-dst="${dst}" title="Show the code behind this data flow">&lt;/&gt;</button>`;

    if (path.includes(pk)) {
      return `<li>${label} <span class="muted">(loops back, already shown above)</span></li>`;
    }
    const kids = [...(childrenOf.get(pk) || [])];
    if (!kids.length) return `<li>${label}</li>`;
    if (depth > dist.get(pk)) {
         return `<li>${label} <span class="muted">(branch shown at hop ${dist.get(pk)})</span></li>`;
       }
       if (shown.has(pk)) {
         return `<li>${label} <span class="muted">(branch already shown above)</span></li>`;
       }
       shown.add(pk);
    if (depth >= MAX_TREE_DEPTH) return `<li>${label} <span class="muted">(more levels not shown)</span></li>`;

    const nextPath = path.concat(pk);
    return `
      <li>
        <details ${depth < 3 ? "open" : ""}>
          <summary>${label} <span class="muted">(${kids.length})</span></summary>
          <ul class="dep-tree">${sortPks(kids).map((k) =>  treeNode(k, childrenOf, nextPath, depth + 1, shown, dist)).join("")}</ul>
        </details>
      </li>`;
  }

  // vulnerability summary for the selected repository (latest scan)
  async function loadVulnSummary(pk) {
    const box = el("dep-vuln-summary");
    box.innerHTML = `<strong>${escapeHtml(shortName(pk))}</strong><div class="muted">Loading vulnerability summary...</div>`;
    try {
      const data = await requestJson(`/api/dependencies/trace/${pk}`);
      if (pk !== selectedPk) return; // user moved on
      box.innerHTML = renderVulnSummary(pk, data.start);
    } catch (err) {
      if (pk !== selectedPk) return;
      box.innerHTML = `<strong>${escapeHtml(shortName(pk))}</strong><div class="dep-error">Could not load vulnerability summary: ${escapeHtml(err.message)}</div>`;
    }
  }

  function renderVulnSummary(pk, start) {
    const order = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
    const counts = start.severity_counts || {};
    const chips = Object.keys(counts)
      .sort((a, b) => {
        const ia = order.indexOf(a), ib = order.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      })
      .map((s) => `<span class="dep-sev dep-sev-${escapeHtml(s.toLowerCase())}">${escapeHtml(s)}: ${counts[s]}</span>`)
      .join("");

    const line =
      start.latest_scan_id === null
        ? "Not scanned yet."
        : `${start.vulnerable_packages} vulnerable package${start.vulnerable_packages === 1 ? "" : "s"} in the latest scan (#${start.latest_scan_id}).`;

    return `
      <strong title="${escapeHtml(fullName(pk))}">${escapeHtml(shortName(pk))}</strong>
      <div class="muted">${escapeHtml(line)}</div>
      ${chips ? `<div class="dep-sev-row">${chips}</div>` : ""}`;
  }

  // ---------- wiring ----------
  function init() {
    if (!el("dependencies-panel")) return;

    el("dep-repo-search").addEventListener("input", renderRepoList);
    el("dep-only-linked").addEventListener("change", renderRepoList);
    el("dep-source-search").addEventListener("input", renderSourceList);
    el("dep-save").addEventListener("click", saveSources);
    el("dep-reset").addEventListener("click", resetSources);
    el("dep-refresh").addEventListener("click", loadAll);
    document.addEventListener("dep:changed", loadAll);

    el("dep-repo-list").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-pk]");
      if (button) selectRepo(Number(button.dataset.pk));
    });

    el("dep-source-list").addEventListener("change", (event) => {
      if (event.target.matches('input[type="checkbox"]')) {
        toggleSource(Number(event.target.value), event.target.checked);
      }
    });

    el("dep-chips").addEventListener("click", (event) => {
      const button = event.target.closest("button[data-pk]");
      if (button) toggleSource(Number(button.dataset.pk), false);
    });
    // clicking </> next to a repository shows the code behind that data flow
    el("dep-tree").addEventListener("click", (event) => {
      const button = event.target.closest("button.dep-ev");
      if (!button) return;
      event.preventDefault(); // don't also open/close the <details>
      window.EvidencePanel.show(shortName(Number(button.dataset.src)), shortName(Number(button.dataset.dst)));
    });
    // clicking a repository in a tree jumps to it
    el("dep-tree").addEventListener("click", (event) => {
      const node = event.target.closest("button.dep-node");
      if (!node) return;
      event.preventDefault(); // don't also open/close the <details>
      selectRepo(Number(node.dataset.pk));
      el("dep-editor-card").scrollIntoView({ behavior: "smooth", block: "start" });
    });

    // reload when the tab is opened, so new targets and changes show up
    const navButton = document.querySelector('.nav-item[data-panel="dependencies-panel"]');
    if (navButton) navButton.addEventListener("click", loadAll);

    loadAll();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
