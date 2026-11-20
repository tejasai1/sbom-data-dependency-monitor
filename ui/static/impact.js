// AI impact report (FlowTrace integration).
// Follows the repository selected in the Data Dependencies tab. On request, asks the
// server for an LLM impact report and shows it as a tree plus a short summary.
// The tree is drawn from the facts (database), never from the model's text.
(function () {
  "use strict";

  const el = (id) => document.getElementById(id);
  const SEVERITIES = [["critical", "C"], ["high", "H"], ["medium", "M"], ["low", "L"]];

  let currentPk = null;
  let requestId = 0;   // ignores answers for a repository the user has moved away from
  let network = null;

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function setStatus(message, kind) {
    const box = el("imp-status");
    box.textContent = message;
    box.classList.toggle("imp-error", kind === "error");
    box.classList.toggle("imp-pending", kind === "pending");
  }

  // ---------- selection from the Data Dependencies tab ----------
  function onSelected(pk, name) {
    currentPk = pk;
    requestId += 1;
    el("imp-empty").classList.add("hidden-panel");
    el("imp-body").classList.remove("hidden-panel");
    el("imp-result").classList.add("hidden-panel");
    el("imp-target").textContent = name;
    el("imp-generate").disabled = false;
    el("imp-regenerate").classList.add("hidden-panel");
    setStatus("Click \"Generate impact report\" to analyze this repository.");
  }

  // ---------- request ----------
  // force = true asks the model for a new report even if a saved one matches.
  async function generate(force) {
    if (currentPk === null) return;
    const myRequest = ++requestId;
    const buttons = [el("imp-generate"), el("imp-regenerate")];
    buttons.forEach((b) => (b.disabled = true));
    el("imp-result").classList.add("hidden-panel");
    setStatus(force ? "Asking the model for a new report..." : "Loading the report...", "pending");

    try {
      const response = await fetch("/api/impact-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: currentPk, force: Boolean(force) }),
      });
      let data = {};
      try {
        data = await response.json();
      } catch (err) {
        data = {};
      }
      if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
      if (myRequest !== requestId) return;
      render(data);
      setStatus(
        data.cached
          ? `Showing the saved report from ${data.created_at} (${data.model}). Nothing has changed since it was made.`
          : `New report generated with ${data.model}.`
      );
      el("imp-regenerate").classList.remove("hidden-panel");
    } catch (err) {
      if (myRequest !== requestId) return;
      setStatus(`Could not generate the report: ${err.message}`, "error");
    } finally {
      if (myRequest === requestId) buttons.forEach((b) => (b.disabled = false));
    }
  }

  // ---------- report ----------
  function render(data) {
    const report = data.report || {};
    const level = String(report.risk_level || "unknown").toLowerCase();

    const risk = el("imp-risk");
    risk.textContent = `Risk: ${level}`;
    risk.className = `imp-risk imp-risk-${level}`;

    const problems = data.problems || [];
    const verify = el("imp-verify");
    verify.textContent = problems.length
      ? `Check failed: ${problems.join("; ")}`
      : "Verified against scan data";
    verify.className = problems.length ? "imp-verify imp-warn" : "imp-verify imp-ok";

    el("imp-summary").textContent = report.summary || "";

    const exposures = (report.key_exposures || []).map((k) =>
      typeof k === "string" ? { system: k, reason: "" } : k
    );
    el("imp-exposures").innerHTML = exposures.length
      ? exposures
          .map((k) => `<li><strong>${escapeHtml(k.system)}</strong>${k.reason ? `: ${escapeHtml(k.reason)}` : ""}</li>`)
          .join("")
      : '<li class="muted">None listed.</li>';

    const recommendations = report.recommendations || [];
    el("imp-recs").innerHTML = recommendations.length
      ? recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join("")
      : '<li class="muted">None listed.</li>';

    el("imp-result").classList.remove("hidden-panel");
    drawTree(data.facts, new Set(exposures.map((k) => String(k.system).toLowerCase())));
  }

  // ---------- visual impact tree ----------
  function colorsFor(counts) {
    if (counts.critical) return { background: "#fde0dc", border: "#b3261e" };
    if (counts.high) return { background: "#fff0db", border: "#e8710a" };
    if (counts.medium) return { background: "#fffbe6", border: "#c9a400" };
    return { background: "#eef4f5", border: "#5e8c93" };
  }

  function countsText(vulns) {
    if (vulns.scanned === false) return "not scanned yet";
    const parts = SEVERITIES.filter(([key]) => vulns.by_severity[key]).map(
      ([key, short]) => `${short}:${vulns.by_severity[key]}`
    );
    return parts.length ? parts.join("  ") : "no findings";
  }

  function drawTree(facts, highlighted) {
    const box = el("imp-graph");
    if (network) {
      network.destroy();
      network = null;
    }
    if (!window.vis) {
      box.innerHTML = '<div class="muted imp-graph-message">Could not load the diagram library (an internet connection is needed).</div>';
      return;
    }

    // A system can be both downstream and upstream when data flows both ways.
    // Draw it once, in its downstream column, so the diagram has one box per system.
    const byName = new Map();
    byName.set(facts.system, { system: facts.system, vulnerabilities: facts.vulnerabilities, focus: true, level: 0 });
    for (const s of facts.downstream) {
      if (!byName.has(s.system)) byName.set(s.system, { ...s, level: s.hops });
    }
    for (const s of facts.upstream) {
      const seen = byName.get(s.system);
      if (seen) seen.alsoUpstream = true;
      else byName.set(s.system, { ...s, level: -s.hops });
    }
    const systems = [...byName.values()];

    const nodes = systems.map((s) => {
      const v = s.vulnerabilities;
      const colors = colorsFor(v.by_severity);
      const isKey = highlighted.has(s.system.toLowerCase());
      const top = (v.most_serious || []).map((m) => `${m.id} (${m.severity})`).join("\n");
      const where = s.focus
        ? "selected repository"
        : `${s.hops} hop${s.hops === 1 ? "" : "s"} ${s.level < 0 ? "upstream" : "downstream"}` +
          (s.alsoUpstream ? ", also sends data to the selected repository" : "");
      return {
        id: s.system,
        level: s.level,
        label: `${s.system}\n${countsText(v)}`,
        shape: "box",
        margin: 10,
        color: { ...colors, highlight: colors, hover: colors },
        borderWidth: s.focus ? 5 : isKey ? 4 : 1,
        font: { size: s.focus ? 16 : 14, color: "#1b2a30" },
        title: `${s.system} (${where})\n${v.scanned === false ? "not scanned yet" : v.total + " vulnerabilities"}${top ? "\n" + top : ""}`,
      };
    });

    const levelOf = new Map(systems.map((s) => [s.system, s.level]));
    const edges = (facts.data_flows || []).map((d) => {
    const edge = {
        from: d.from,
        to: d.to,
        arrows: "to",
        color: { color: "#5b6b70" },
        title: "Click to see the code behind this data flow",
      };
    const fromLevel = levelOf.get(d.from);
    const toLevel = levelOf.get(d.to);
      if (fromLevel === toLevel) {
        // Both systems are the same number of hops away: curve the line around the
        // column instead of drawing it straight through the boxes in between.
        edge.smooth = { enabled: true, type: "curvedCW", roundness: 0.7 };
      } else if (fromLevel > toLevel) {
        // Data flowing back toward the left (a two-way link): curve it so it doesn't
        // sit on top of the forward arrow.
        edge.smooth = { enabled: true, type: "curvedCW", roundness: 0.3 };
      }
      return edge;
    });

    const edgeSet = new vis.DataSet(edges);
    network = new vis.Network(
      box,
      { nodes: new vis.DataSet(nodes), edges: edgeSet },
      {
        layout: {
          hierarchical: { direction: "LR", sortMethod: "directed", levelSeparation: 260, nodeSpacing: 85 },
        },
        physics: false,
        interaction: { hover: true, tooltipDelay: 150 },
        edges: { smooth: { type: "cubicBezier", forceDirection: "horizontal", roundness: 0.4 } },
      }
    );
    // Zoom so the tree fills the box (vis-network stops at 100% by default).
    network.fit({ maxZoomLevel: 1.6, animation: false });
    // Clicking an arrow shows the code behind that data flow (like FlowTrace's map).
    network.on("click", (params) => {
      if (!params.edges.length || params.nodes.length) return; // only a click on an arrow
      const edge = edgeSet.get(params.edges[0]);
      if (edge && window.EvidencePanel) window.EvidencePanel.show(edge.from, edge.to);
    });
  }


  // ---------- wiring ----------
  function init() {
    if (!el("imp-card")) return;
    el("imp-generate").addEventListener("click", () => generate(false));
    el("imp-regenerate").addEventListener("click", () => generate(true));
    document.addEventListener("dep:selected", (event) => {
      onSelected(event.detail.pk, event.detail.name);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
