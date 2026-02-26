(function () {
  const root = document.getElementById("auditRoot");
  if (!root) {
    return;
  }

  const ticketId = root.getAttribute("data-ticket-id");
  if (!ticketId) {
    return;
  }

  const auditTitleEl = document.getElementById("auditTitle");
  const auditSubtitleEl = document.getElementById("auditSubtitle");
  const backToTicket = document.getElementById("backToTicket");
  const graphStatsEl = document.getElementById("graphStats");
  const auditDiagramEl = document.getElementById("auditDiagram");
  const nodeDetailMetaEl = document.getElementById("nodeDetailMeta");
  const nodeDetailBodyEl = document.getElementById("nodeDetailBody");

  const state = {
    nodes: [],
    selectedNodeId: null,
  };

  const NODE_TYPE_STYLE = {
    agent: { bg: "#0d2233", border: "#1a5a7a", text: "#4dcfff", label: "agent" },
    tool: { bg: "#12201a", border: "#1a5a35", text: "#4dff8f", label: "tool" },
    default: { bg: "#1a1a2e", border: "#2a2a5a", text: "#8888cc", label: "node" },
  };

  const COL_WIDTH = 220;
  const ROW_HEIGHT = 90;
  const NODE_W = 180;
  const NODE_H = 58;
  const PAD_X = 40;
  const PAD_Y = 40;

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function typeStyle(nodeType) {
    return NODE_TYPE_STYLE[nodeType] || NODE_TYPE_STYLE.default;
  }

  function buildEdges(nodes) {
    const byId = new Map(nodes.map((node) => [node.id, node]));
    return nodes
      .filter((node) => node.parent_id)
      .map((node) => {
        const parent = byId.get(node.parent_id);
        if (!parent) {
          return null;
        }
        return { id: node.id, from: parent, to: node };
      })
      .filter(Boolean);
  }

  function fallbackLayout(nodes, edges) {
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const indegree = new Map(nodes.map((node) => [node.id, 0]));
    const outgoing = new Map(nodes.map((node) => [node.id, []]));

    edges.forEach((edge) => {
      const fromId = edge.from.id;
      const toId = edge.to.id;
      indegree.set(toId, (indegree.get(toId) || 0) + 1);
      outgoing.get(fromId).push(toId);
    });

    const queue = [];
    indegree.forEach((degree, nodeId) => {
      if (degree === 0) {
        queue.push(nodeId);
      }
    });

    const level = new Map();
    queue.forEach((nodeId) => level.set(nodeId, 0));

    while (queue.length) {
      const current = queue.shift();
      const base = level.get(current) || 0;
      (outgoing.get(current) || []).forEach((next) => {
        level.set(next, Math.max(level.get(next) || 0, base + 1));
        indegree.set(next, (indegree.get(next) || 0) - 1);
        if ((indegree.get(next) || 0) === 0) {
          queue.push(next);
        }
      });
    }

    const groups = new Map();
    nodes.forEach((node) => {
      const col = level.get(node.id) || 0;
      if (!groups.has(col)) {
        groups.set(col, []);
      }
      groups.get(col).push(node.id);
    });

    groups.forEach((ids, col) => {
      ids.forEach((id, row) => {
        const node = byId.get(id);
        node.col = col;
        node.row = row;
      });
    });

    return nodes;
  }

  function normalizeNodes(rawNodes, rawEdges) {
    const nodes = Array.isArray(rawNodes)
      ? rawNodes.map((node) => ({
          ...node,
          name: node.name || node.label || node.id,
          node_type: node.node_type || node.type || "default",
          row: Number.isFinite(Number(node.row)) ? Number(node.row) : null,
          col: Number.isFinite(Number(node.col)) ? Number(node.col) : null,
        }))
      : [];

    if (!nodes.length) {
      return [];
    }

    // Backfill parent links from legacy edges if parent_id is missing.
    if (Array.isArray(rawEdges) && rawEdges.length) {
      const byId = new Map(nodes.map((node) => [node.id, node]));
      rawEdges.forEach((edge) => {
        const toNode = byId.get(edge.to);
        if (toNode && !toNode.parent_id) {
          toNode.parent_id = edge.from;
        }
      });
    }

    const hasExplicitCoords = nodes.every((node) => node.col !== null && node.row !== null);
    if (hasExplicitCoords) {
      return nodes;
    }

    const edges = buildEdges(nodes);
    return fallbackLayout(nodes, edges);
  }

  function nodePos(node) {
    const x = PAD_X + (node.col || 0) * COL_WIDTH + (COL_WIDTH - NODE_W) / 2;
    const y = PAD_Y + (node.row || 0) * ROW_HEIGHT + (ROW_HEIGHT - NODE_H) / 2;
    return { x, y, cx: x + NODE_W / 2, cy: y + NODE_H / 2 };
  }

  function renderNodeDetails(node) {
    if (!node) {
      nodeDetailMetaEl.textContent = "Select a node.";
      nodeDetailBodyEl.textContent = "";
      return;
    }

    const role = node.node_type || "node";
    nodeDetailMetaEl.textContent = `${node.name} (${role})`;

    const payload = {
      input: node.input_data || "",
      output: node.output_data || "",
      duration_ms: node.duration_ms,
      records: node.record_count,
      worker: node.worker,
    };
    nodeDetailBodyEl.textContent = JSON.stringify(payload, null, 2);
  }

  function renderGraph(nodes) {
    if (!Array.isArray(nodes) || !nodes.length) {
      auditDiagramEl.innerHTML = '<div class="empty-state">No audit graph data available for this ticket.</div>';
      graphStatsEl.textContent = "0 nodes";
      renderNodeDetails(null);
      return;
    }

    const cols = Math.max(...nodes.map((node) => node.col || 0), 0) + 1;
    const rows = Math.max(...nodes.map((node) => node.row || 0), 0) + 1;
    const svgW = cols * COL_WIDTH + PAD_X * 2;
    const svgH = rows * ROW_HEIGHT + PAD_Y * 2;

    const edges = buildEdges(nodes);

    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("width", String(svgW));
    svg.setAttribute("height", String(svgH));
    svg.style.minWidth = `${svgW}px`;

    const defs = document.createElementNS(svgNS, "defs");
    const marker = document.createElementNS(svgNS, "marker");
    marker.setAttribute("id", "arrow");
    marker.setAttribute("markerWidth", "8");
    marker.setAttribute("markerHeight", "8");
    marker.setAttribute("refX", "6");
    marker.setAttribute("refY", "3");
    marker.setAttribute("orient", "auto");
    const markerPath = document.createElementNS(svgNS, "path");
    markerPath.setAttribute("d", "M0,0 L0,6 L8,3 z");
    markerPath.setAttribute("fill", "#1e3a4a");
    marker.appendChild(markerPath);
    defs.appendChild(marker);
    svg.appendChild(defs);

    edges.forEach((edge) => {
      const from = nodePos(edge.from);
      const to = nodePos(edge.to);
      const line = document.createElementNS(svgNS, "line");
      line.setAttribute("x1", String(from.cx));
      line.setAttribute("y1", String(from.cy));
      line.setAttribute("x2", String(to.cx));
      line.setAttribute("y2", String(to.cy));
      line.setAttribute("stroke", "#1e3a4a");
      line.setAttribute("stroke-width", "1.5");
      line.setAttribute("marker-end", "url(#arrow)");
      svg.appendChild(line);
    });

    nodes.forEach((node) => {
      const pos = nodePos(node);
      const style = typeStyle(node.node_type);
      const isSelected = state.selectedNodeId === node.id;

      const group = document.createElementNS(svgNS, "g");
      group.style.cursor = "pointer";

      const rect = document.createElementNS(svgNS, "rect");
      rect.setAttribute("x", String(pos.x));
      rect.setAttribute("y", String(pos.y));
      rect.setAttribute("width", String(NODE_W));
      rect.setAttribute("height", String(NODE_H));
      rect.setAttribute("rx", "8");
      rect.setAttribute("fill", style.bg);
      rect.setAttribute("stroke", isSelected ? "#00d4ff" : style.border);
      rect.setAttribute("stroke-width", isSelected ? "2" : "1");
      group.appendChild(rect);

      const title = document.createElementNS(svgNS, "text");
      title.setAttribute("x", String(pos.x + 12));
      title.setAttribute("y", String(pos.y + 20));
      title.setAttribute("fill", style.text);
      title.setAttribute("font-size", "11");
      title.setAttribute("font-family", "monospace");
      title.setAttribute("font-weight", "600");
      const nodeName = String(node.name || node.id);
      title.textContent = nodeName.length > 22 ? `${nodeName.slice(0, 22)}…` : nodeName;
      group.appendChild(title);

      const subtitle = document.createElementNS(svgNS, "text");
      subtitle.setAttribute("x", String(pos.x + 12));
      subtitle.setAttribute("y", String(pos.y + 38));
      subtitle.setAttribute("fill", "#4a6070");
      subtitle.setAttribute("font-size", "9");
      subtitle.setAttribute("font-family", "monospace");
      const workerLabel = node.worker !== null && node.worker !== undefined ? ` | W${node.worker}` : "";
      const recordCount = node.record_count || 1;
      subtitle.textContent = `${style.label}${workerLabel} | ${recordCount} record${recordCount !== 1 ? "s" : ""}`;
      group.appendChild(subtitle);

      if (node.duration_ms !== null && node.duration_ms !== undefined) {
        const duration = document.createElementNS(svgNS, "text");
        duration.setAttribute("x", String(pos.x + NODE_W - 8));
        duration.setAttribute("y", String(pos.y + 38));
        duration.setAttribute("fill", "#2a5060");
        duration.setAttribute("font-size", "8");
        duration.setAttribute("font-family", "monospace");
        duration.setAttribute("text-anchor", "end");
        duration.textContent = `${node.duration_ms}ms`;
        group.appendChild(duration);
      }

      group.addEventListener("click", () => {
        state.selectedNodeId = node.id;
        renderGraph(state.nodes);
        renderNodeDetails(node);
      });

      svg.appendChild(group);
    });

    auditDiagramEl.innerHTML = "";
    auditDiagramEl.appendChild(svg);
    graphStatsEl.textContent = `${nodes.length} nodes | ${edges.length} edges`;

    const selected = nodes.find((node) => node.id === state.selectedNodeId) || nodes[0];
    if (!state.selectedNodeId && selected) {
      state.selectedNodeId = selected.id;
    }
    renderNodeDetails(selected || null);
  }

  async function loadAudit() {
    try {
      const response = await fetch(`/api/tickets/${ticketId}/audit`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to load audit graph");
      }

      auditTitleEl.textContent = `LLM Auditability | ${data.ticket.ticket_key}`;
      auditSubtitleEl.textContent = `${data.ticket.title} | Status: ${data.ticket.status}`;
      backToTicket.href = `/tickets/${ticketId}`;

      state.nodes = normalizeNodes(data.graph?.nodes || [], data.graph?.edges || []);
      renderGraph(state.nodes);
    } catch (error) {
      auditDiagramEl.innerHTML = `<div class="empty-state">${escapeHtml(error.message || "Failed to load audit data")}</div>`;
      graphStatsEl.textContent = "0 nodes";
      renderNodeDetails(null);
    }
  }

  loadAudit();
})();
