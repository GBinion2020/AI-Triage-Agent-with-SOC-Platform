(function () {
  const startBtn = document.getElementById("startPipelineBtn");
  const llmProviderSelect = document.getElementById("llmProvider");
  const pipelineArchSelect = document.getElementById("pipelineArch");
  const runStatusEl = document.getElementById("runStatus");
  const runSessionEl = document.getElementById("runSession");
  const runTicketEl = document.getElementById("runTicket");
  const liveLogEl = document.getElementById("liveLog");
  const clearLogBtn = document.getElementById("clearLogBtn");
  const ticketTableBody = document.getElementById("ticketTableBody");
  const ticketSearch = document.getElementById("ticketSearch");
  const ticketStatusFilter = document.getElementById("ticketStatusFilter");
  const criticalOnlyToggle = document.getElementById("criticalOnlyToggle");
  const queueCountEl = document.getElementById("queueCount");
  const inProgressCountEl = document.getElementById("inProgressCount");
  const overdueCountEl = document.getElementById("overdueCount");
  const criticalCountEl = document.getElementById("criticalCount");
  const resolvedCountEl = document.getElementById("resolvedCount");
  const dashboardDateEl = document.getElementById("dashboardDate");

  const state = {
    cursor: 0,
    sessionId: null,
    lastTicketId: null,
    statusTimer: null,
    logTimer: null,
    ticketTimer: null,
    searchDebounce: null,
  };

  function statusLabel(raw) {
    const value = String(raw || "").toLowerCase();
    if (value === "to_do") {
      return "To Do";
    }
    if (value === "in_progress") {
      return "In Progress";
    }
    if (value === "done") {
      return "Done";
    }
    if (value === "completed_no_alerts") {
      return "Completed (No Alerts)";
    }
    if (value === "completed") {
      return "Completed";
    }
    if (value === "failed") {
      return "Failed";
    }
    return value || "Unknown";
  }

  function severityLabel(raw) {
    const value = String(raw || "unknown").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(value)) {
      return value;
    }
    return "unknown";
  }

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function getSlaHours(severity) {
    switch (String(severity || "").toLowerCase()) {
      case "critical":
        return 4;
      case "high":
        return 8;
      case "medium":
        return 24;
      case "low":
        return 72;
      default:
        return 48;
    }
  }

  function slaState(ticket) {
    const createdAt = ticket.created_at ? new Date(ticket.created_at) : null;
    if (!createdAt || Number.isNaN(createdAt.getTime())) {
      return { label: "SLA n/a", className: "", overdue: false };
    }

    const dueAtMs = createdAt.getTime() + getSlaHours(ticket.severity) * 3600 * 1000;
    const nowMs = Date.now();
    const deltaMin = Math.round((dueAtMs - nowMs) / 60000);

    if (deltaMin < 0) {
      const late = Math.abs(deltaMin);
      if (late < 60) {
        return { label: `${late}m overdue`, className: "overdue", overdue: true };
      }
      return { label: `${Math.round(late / 60)}h overdue`, className: "overdue", overdue: true };
    }

    if (deltaMin <= 120) {
      if (deltaMin < 60) {
        return { label: `${deltaMin}m left`, className: "due-soon", overdue: false };
      }
      return { label: `${Math.round(deltaMin / 60)}h left`, className: "due-soon", overdue: false };
    }

    return { label: `${Math.round(deltaMin / 60)}h left`, className: "", overdue: false };
  }

  function shortDate(value) {
    if (!value) {
      return "-";
    }
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) {
      return "-";
    }
    return dt.toLocaleString();
  }

  function appendLogLines(lines) {
    if (!Array.isArray(lines) || !lines.length) {
      return;
    }

    const nearBottom = liveLogEl.scrollTop + liveLogEl.clientHeight >= liveLogEl.scrollHeight - 24;
    const text = lines.join("\n");
    if (liveLogEl.textContent && !liveLogEl.textContent.endsWith("\n")) {
      liveLogEl.textContent += "\n";
    }
    liveLogEl.textContent += text;

    if (nearBottom) {
      liveLogEl.scrollTop = liveLogEl.scrollHeight;
    }
  }

  function renderTodayLabel() {
    if (!dashboardDateEl) {
      return;
    }
    try {
      dashboardDateEl.textContent = new Date().toLocaleDateString(undefined, {
        weekday: "long",
        year: "numeric",
        month: "long",
        day: "numeric",
      });
    } catch (_error) {
      dashboardDateEl.textContent = "Security case operations and live pipeline control.";
    }
  }

  function setRunTicket(ticketId) {
    if (!ticketId) {
      runTicketEl.textContent = "-";
      return;
    }

    runTicketEl.innerHTML = `<a href="/tickets/${ticketId}" class="mono">Ticket #${ticketId}</a>`;
  }

  async function startPipeline() {
    const payload = {
      llm_provider: llmProviderSelect.value,
      pipeline_arch: pipelineArchSelect.value,
    };

    startBtn.disabled = true;

    try {
      const response = await fetch("/api/pipeline/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to start pipeline");
      }

      liveLogEl.textContent = "";
      state.cursor = 0;
      state.sessionId = data.session_id;
      state.lastTicketId = null;

      runStatusEl.textContent = "Running";
      runSessionEl.textContent = data.session_id;
      setRunTicket(null);

      await Promise.all([pollStatus(), pollLogs(), loadTickets(), loadQueueSummary()]);
    } catch (error) {
      alert(error.message || "Failed to start pipeline");
    } finally {
      startBtn.disabled = false;
    }
  }

  async function pollStatus() {
    try {
      const response = await fetch("/api/pipeline/status", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to read status");
      }

      runStatusEl.textContent = statusLabel(data.status);
      runSessionEl.textContent = data.session_id || "-";
      if (data.ticket_id) {
        state.lastTicketId = data.ticket_id;
      }
      setRunTicket(state.lastTicketId || data.ticket_id || null);

      if (data.active) {
        startBtn.disabled = true;
      } else {
        startBtn.disabled = false;
      }
    } catch (_error) {
      // Keep UI usable if status endpoint is temporarily unavailable.
    }
  }

  async function pollLogs() {
    try {
      const response = await fetch(`/api/pipeline/logs?cursor=${state.cursor}`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to read logs");
      }

      const incomingSession = data.session_id;
      if (incomingSession && state.sessionId && incomingSession !== state.sessionId) {
        state.sessionId = incomingSession;
        state.cursor = 0;
        liveLogEl.textContent = "";
      }
      if (incomingSession && !state.sessionId) {
        state.sessionId = incomingSession;
      }

      appendLogLines(data.lines || []);
      state.cursor = Number(data.next_cursor || 0);

      if (data.ticket_id) {
        state.lastTicketId = data.ticket_id;
        setRunTicket(data.ticket_id);
      }

      if (data.completed) {
        startBtn.disabled = false;
      }
    } catch (_error) {
      // Ignore transient polling errors.
    }
  }

  function renderTickets(tickets) {
    if (!Array.isArray(tickets) || !tickets.length) {
      ticketTableBody.innerHTML = '<tr><td colspan="5" class="ticket-sub">No tickets found.</td></tr>';
      return;
    }

    const rows = tickets
      .map((ticket) => {
        const severity = severityLabel(ticket.severity);
        const sla = slaState(ticket);
        const classification = ticket.classification || "-";
        return `
          <tr data-ticket-id="${ticket.id}">
            <td>
              <div class="ticket-main-cell">
                <strong>${escapeHtml(ticket.ticket_key)}</strong>
                <span class="ticket-sub">${escapeHtml(ticket.title || "Untitled alert")}</span>
                <span class="ticket-sub mono">Created: ${escapeHtml(shortDate(ticket.created_at))}</span>
              </div>
            </td>
            <td>
              <span class="badge severity-${severity}">${escapeHtml(severity)}</span>
            </td>
            <td>
              <span class="sla-badge ${sla.className}">${escapeHtml(sla.label)}</span>
              <div class="ticket-sub">Created: ${escapeHtml(shortDate(ticket.created_at))}</div>
            </td>
            <td>
              <span class="badge ${escapeHtml(ticket.status || "")}">${escapeHtml(statusLabel(ticket.status))}</span>
            </td>
            <td>${escapeHtml(classification)}</td>
          </tr>
        `;
      })
      .join("");

    ticketTableBody.innerHTML = rows;
    ticketTableBody.querySelectorAll("tr[data-ticket-id]").forEach((row) => {
      row.addEventListener("click", () => {
        const ticketId = row.getAttribute("data-ticket-id");
        if (ticketId) {
          window.location.href = `/tickets/${ticketId}`;
        }
      });
    });
  }

  async function loadTickets() {
    const status = ticketStatusFilter.value || "all";
    const query = (ticketSearch.value || "").trim();

    try {
      const response = await fetch(`/api/tickets?status=${encodeURIComponent(status)}&q=${encodeURIComponent(query)}`, {
        cache: "no-store",
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to load tickets");
      }

      const tickets = Array.isArray(data.tickets) ? data.tickets : [];
      const showCriticalOnly = criticalOnlyToggle.checked;
      const filtered = showCriticalOnly
        ? tickets.filter((ticket) => {
            const sev = severityLabel(ticket.severity);
            return sev === "critical" || sev === "high";
          })
        : tickets;

      renderTickets(filtered);
    } catch (_error) {
      ticketTableBody.innerHTML = '<tr><td colspan="5" class="ticket-sub">Unable to load tickets.</td></tr>';
    }
  }

  async function loadQueueSummary() {
    try {
      const response = await fetch("/api/tickets?status=all&q=", { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to load queue");
      }

      const tickets = Array.isArray(data.tickets) ? data.tickets : [];
      const inProgress = tickets.filter((ticket) => String(ticket.status) === "in_progress").length;
      const critical = tickets.filter((ticket) => severityLabel(ticket.severity) === "critical").length;
      const resolved = tickets.filter((ticket) => String(ticket.status) === "done").length;
      const overdue = tickets.filter((ticket) => slaState(ticket).overdue).length;

      queueCountEl.textContent = String(tickets.length);
      inProgressCountEl.textContent = String(inProgress);
      overdueCountEl.textContent = String(overdue);
      if (criticalCountEl) {
        criticalCountEl.textContent = String(critical);
      }
      if (resolvedCountEl) {
        resolvedCountEl.textContent = String(resolved);
      }
    } catch (_error) {
      queueCountEl.textContent = "-";
      inProgressCountEl.textContent = "-";
      overdueCountEl.textContent = "-";
      if (criticalCountEl) {
        criticalCountEl.textContent = "-";
      }
      if (resolvedCountEl) {
        resolvedCountEl.textContent = "-";
      }
    }
  }

  function bindEvents() {
    startBtn.addEventListener("click", startPipeline);

    clearLogBtn.addEventListener("click", () => {
      liveLogEl.textContent = "";
      state.cursor = 0;
    });

    ticketStatusFilter.addEventListener("change", () => {
      loadTickets();
    });

    criticalOnlyToggle.addEventListener("change", () => {
      loadTickets();
    });

    ticketSearch.addEventListener("input", () => {
      if (state.searchDebounce) {
        clearTimeout(state.searchDebounce);
      }
      state.searchDebounce = window.setTimeout(loadTickets, 260);
    });
  }

  function startPolling() {
    state.statusTimer = window.setInterval(pollStatus, 2500);
    state.logTimer = window.setInterval(pollLogs, 1200);
    state.ticketTimer = window.setInterval(() => {
      loadTickets();
      loadQueueSummary();
    }, 9000);
  }

  bindEvents();
  renderTodayLabel();
  startPolling();
  pollStatus();
  pollLogs();
  loadTickets();
  loadQueueSummary();
})();
