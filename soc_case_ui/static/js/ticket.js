(function () {
  const root = document.getElementById("ticketRoot");
  if (!root) {
    return;
  }

  const ticketId = root.getAttribute("data-ticket-id");
  if (!ticketId) {
    return;
  }

  const ticketTitleEl = document.getElementById("ticketTitle");
  const ticketSubtitleEl = document.getElementById("ticketSubtitle");
  const ticketSlaLineEl = document.getElementById("ticketSlaLine");
  const statusSelect = document.getElementById("statusSelect");
  const classificationSelect = document.getElementById("classificationSelect");
  const verdictSelect = document.getElementById("verdictSelect");
  const closeNoteInput = document.getElementById("closeNote");
  const saveTicketBtn = document.getElementById("saveTicketBtn");
  const saveTicketMsg = document.getElementById("saveTicketMsg");
  const investigationStepsEl = document.getElementById("investigationSteps");
  const runHealthEl = document.getElementById("runHealth");
  const commentListEl = document.getElementById("commentList");
  const commentAuthorInput = document.getElementById("commentAuthor");
  const commentBodyInput = document.getElementById("commentBody");
  const addCommentBtn = document.getElementById("addCommentBtn");
  const activityListEl = document.getElementById("activityList");
  const auditLink = document.getElementById("auditLink");
  const downloadCaseLink = document.getElementById("downloadCaseLink");
  const templateButtons = Array.from(document.querySelectorAll(".template-btn"));
  const resultClassificationEl = document.getElementById("resultClassification");
  const resultVerdictEl = document.getElementById("resultVerdict");
  const resultScoreEl = document.getElementById("resultScore");
  const resultSummaryEl = document.getElementById("resultSummary");
  const iocChipsEl = document.getElementById("iocChips");
  const evidenceTableBodyEl = document.getElementById("evidenceTableBody");
  const detailSeverityEl = document.getElementById("detailSeverity");
  const detailStatusEl = document.getElementById("detailStatus");
  const detailCreatedEl = document.getElementById("detailCreated");

  const state = {
    ticket: null,
  };

  function setFatalError(message) {
    if (ticketTitleEl) {
      ticketTitleEl.textContent = "Case view unavailable";
    }
    if (ticketSubtitleEl) {
      ticketSubtitleEl.textContent = message || "Unexpected rendering error.";
    }
    if (root) {
      root.style.display = "grid";
    }
  }

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

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
    return value || "Unknown";
  }

  function severityLabel(raw) {
    const value = String(raw || "unknown").toLowerCase();
    if (["critical", "high", "medium", "low"].includes(value)) {
      return value;
    }
    return "unknown";
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

  function computeSla(ticket) {
    const createdAt = ticket.created_at ? new Date(ticket.created_at) : null;
    if (!createdAt || Number.isNaN(createdAt.getTime())) {
      return "SLA unavailable";
    }

    const hours = getSlaHours(ticket.severity);
    const dueAt = new Date(createdAt.getTime() + hours * 3600 * 1000);
    const deltaMs = dueAt.getTime() - Date.now();
    const deltaMin = Math.round(deltaMs / 60000);

    if (deltaMin < 0) {
      const overdueMin = Math.abs(deltaMin);
      if (overdueMin < 60) {
        return `SLA: overdue by ${overdueMin}m (target ${hours}h for ${severityLabel(ticket.severity)} severity)`;
      }
      return `SLA: overdue by ${Math.round(overdueMin / 60)}h (target ${hours}h for ${severityLabel(ticket.severity)} severity)`;
    }

    if (deltaMin < 60) {
      return `SLA: ${deltaMin}m remaining (due ${dueAt.toLocaleString()})`;
    }

    return `SLA: ${Math.round(deltaMin / 60)}h remaining (due ${dueAt.toLocaleString()})`;
  }

  function normalizeClassification(value) {
    const normalized = String(value || "").trim().toLowerCase().replaceAll(" ", "_");
    if (["benign", "suspicious", "malicious", "false_positive"].includes(normalized)) {
      return normalized;
    }
    return "";
  }

  function normalizeVerdict(value) {
    const normalized = String(value || "").trim().toLowerCase().replaceAll(" ", "_");
    const map = {
      close: "close",
      escalate_to_incident_response: "escalate_to_ir",
      escalate_to_ir: "escalate_to_ir",
      block_asset_user: "block_asset_user",
      monitor: "monitor",
    };
    return map[normalized] || "";
  }

  function setMessage(text, mode) {
    saveTicketMsg.className = "inline-msg";
    if (mode === "ok") {
      saveTicketMsg.classList.add("ok");
    }
    if (mode === "error") {
      saveTicketMsg.classList.add("error");
    }
    saveTicketMsg.textContent = text || "";
  }

  function normalizeToolLabel(value) {
    return String(value || "")
      .replace(/\s*\(w\d+_a\d+_[a-f0-9]+\)\s*$/i, "")
      .replace(/\s+/g, " ")
      .trim();
  }

  function renderInvestigationSteps(overview) {
    if (!investigationStepsEl) {
      return;
    }

    const steps = Array.isArray(overview && overview.triage_journal) ? overview.triage_journal : [];
    if (!steps.length) {
      investigationStepsEl.innerHTML = '<div class="empty-state">No investigation steps recorded yet.</div>';
      return;
    }

    investigationStepsEl.innerHTML = steps
      .slice(0, 100)
      .map(
        (step, index) => `
          <article class="investigation-step">
            <div class="investigation-step-head">
              <span class="mono">#${String(index + 1).padStart(2, "0")}</span>
              <strong>${escapeHtml(step.agent || "Agent")}</strong>
              <span class="ticket-sub mono">${escapeHtml(step.timestamp || "")}</span>
            </div>
            <div class="investigation-step-action">${escapeHtml(step.action || "Recorded step")}</div>
            ${
              step.finding
                ? `<pre class="investigation-step-finding mono">${escapeHtml(
                    typeof step.finding === "string" ? step.finding : JSON.stringify(step.finding, null, 2)
                  )}</pre>`
                : ""
            }
          </article>
        `
      )
      .join("");
  }

  function renderRunHealth(runHealth) {
    if (!runHealth || !runHealth.available) {
      runHealthEl.innerHTML = '<div class="status-card"><div class="label">Run Data</div><div class="value">Not available</div></div>';
      return;
    }

    const confidenceRaw = runHealth.confidence;
    const confidenceValue = typeof confidenceRaw === "number"
      ? `${confidenceRaw.toFixed(1)}%`
      : confidenceRaw && typeof confidenceRaw.score === "number"
        ? `${Number(confidenceRaw.score).toFixed(1)}%`
        : "n/a";

    runHealthEl.innerHTML = `
      <div class="status-card">
        <div class="label">Run ID</div>
        <div class="value mono">${escapeHtml(runHealth.run_id || "-")}</div>
      </div>
      <div class="status-card">
        <div class="label">Waves</div>
        <div class="value">${escapeHtml(String(runHealth.waves || 0))}</div>
      </div>
      <div class="status-card">
        <div class="label">Actions</div>
        <div class="value">${escapeHtml(String(runHealth.total_actions || 0))}</div>
      </div>
      <div class="status-card">
        <div class="label">Success Rate</div>
        <div class="value">${escapeHtml(String(runHealth.success_rate || 0))}%</div>
      </div>
      <div class="status-card">
        <div class="label">Confidence</div>
        <div class="value">${escapeHtml(confidenceValue)}</div>
      </div>
      <div class="status-card">
        <div class="label">Failures</div>
        <div class="value">${runHealth.has_failures ? "Yes" : "No"}</div>
      </div>
    `;
  }

  function renderCaseOverview(overview, ticket) {
    const safe = overview || {};
    if (resultClassificationEl) {
      resultClassificationEl.textContent = String(safe.classification || ticket.classification || "unclassified");
    }
    if (resultVerdictEl) {
      resultVerdictEl.textContent = String(safe.verdict || ticket.verdict || ticket.action || "pending");
    }
    if (resultScoreEl) {
      const score = typeof safe.risk_score === "number" ? safe.risk_score : ticket.risk_score;
      resultScoreEl.textContent = score === null || score === undefined || Number.isNaN(Number(score)) ? "0" : String(Math.round(Number(score)));
    }
    if (resultSummaryEl) {
      resultSummaryEl.textContent = String(safe.summary || "No triage summary available.");
    }

    if (detailSeverityEl) {
      detailSeverityEl.textContent = severityLabel(ticket.severity);
    }
    if (detailStatusEl) {
      detailStatusEl.textContent = statusLabel(ticket.status);
    }
    if (detailCreatedEl) {
      detailCreatedEl.textContent = shortDate(ticket.created_at);
    }

    if (iocChipsEl) {
      const iocs = Array.isArray(safe.iocs) ? safe.iocs : [];
      if (!iocs.length) {
        iocChipsEl.innerHTML = '<div class="empty-state">No IOC artifacts extracted yet.</div>';
      } else {
        iocChipsEl.innerHTML = iocs
          .slice(0, 24)
          .map((ioc) => {
            const type = String(ioc.type || "ioc").toLowerCase();
            const value = escapeHtml(ioc.value || "");
            const sourceTool = escapeHtml(normalizeToolLabel(ioc.source_tool || ""));
            return `<span class=\"ioc-chip ${type}\">[${escapeHtml(type.toUpperCase())}] ${value}${sourceTool ? ` | ${sourceTool}` : ""}</span>`;
          })
          .join("");
      }
    }

    if (evidenceTableBodyEl) {
      const events = Array.isArray(safe.events) ? safe.events : [];
      if (!events.length) {
        evidenceTableBodyEl.innerHTML = '<tr><td colspan="4" class="ticket-sub">No evidence events captured for this case yet.</td></tr>';
      } else {
        evidenceTableBodyEl.innerHTML = events
          .slice(0, 80)
          .map((event) => {
            return `
              <tr>
                <td>${escapeHtml(event.timestamp || "-")}</td>
                <td>${escapeHtml(event.event || "Evidence")}</td>
                <td>${escapeHtml(normalizeToolLabel(event.source_tool || "-"))}</td>
                <td>${escapeHtml(event.description || "")}</td>
              </tr>
            `;
          })
          .join("");
      }
    }
  }

  function renderComments(comments) {
    if (!Array.isArray(comments) || !comments.length) {
      commentListEl.innerHTML = '<div class="empty-state">No comments yet.</div>';
      return;
    }

    commentListEl.innerHTML = comments
      .map(
        (comment) => `
          <article class="comment-item">
            <div class="meta">
              <span>${escapeHtml(comment.author || "analyst")}</span>
              <span>${escapeHtml(shortDate(comment.created_at))}</span>
            </div>
            <div>${escapeHtml(comment.body || "")}</div>
          </article>
        `
      )
      .join("");

    commentListEl.scrollTop = commentListEl.scrollHeight;
  }

  function renderActivities(activities) {
    if (!Array.isArray(activities) || !activities.length) {
      activityListEl.innerHTML = '<li class="ticket-sub">No activity yet.</li>';
      return;
    }

    activityListEl.innerHTML = activities
      .slice(-60)
      .map((item) => {
        const details = item.details ? JSON.stringify(item.details) : "";
        return `<li><strong>${escapeHtml(item.event_type)}</strong> <span class="ticket-sub">${escapeHtml(shortDate(item.created_at))}</span><br><span class="ticket-sub mono">${escapeHtml(details)}</span></li>`;
      })
      .join("");
  }

  function renderTicket(payload) {
    try {
      const ticket = payload.ticket;
      state.ticket = ticket;

      ticketTitleEl.textContent = `${ticket.ticket_key} | ${ticket.title || "Untitled"}`;
      ticketSubtitleEl.textContent = `${severityLabel(ticket.severity)} severity | created ${shortDate(ticket.created_at)}`;
      ticketSlaLineEl.textContent = computeSla(ticket);

      statusSelect.value = ticket.status || "to_do";
      classificationSelect.value = normalizeClassification(ticket.classification);
      verdictSelect.value = normalizeVerdict(ticket.verdict || ticket.action);
      closeNoteInput.value = ticket.close_note || "";

      auditLink.href = `/tickets/${ticket.id}/audit`;
      downloadCaseLink.href = `/api/tickets/${ticket.id}/case/download`;

      renderInvestigationSteps(payload.case_overview || {});
      renderRunHealth(payload.run_health);
      renderCaseOverview(payload.case_overview, ticket);
      renderComments(payload.comments || []);
      renderActivities(payload.activities || []);
    } catch (error) {
      setFatalError(error && error.message ? error.message : "Failed to render ticket payload.");
    }
  }

  async function loadTicket() {
    try {
      const response = await fetch(`/api/tickets/${ticketId}`, { cache: "no-store" });
      const text = await response.text();
      let data = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch (_error) {
        data = { detail: text || "Invalid payload" };
      }
      if (!response.ok) {
        throw new Error(data.detail || "Failed to load ticket");
      }
      renderTicket(data);
    } catch (error) {
      ticketTitleEl.textContent = "Failed to load ticket";
      ticketSubtitleEl.textContent = error.message || "Unknown error";
    }
  }

  async function saveTicket() {
    const payload = {
      status: statusSelect.value,
      classification: classificationSelect.value || null,
      verdict: verdictSelect.value || null,
      close_note: closeNoteInput.value || null,
    };

    saveTicketBtn.disabled = true;
    setMessage("Saving...", "");

    try {
      const response = await fetch(`/api/tickets/${ticketId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to save ticket");
      }

      setMessage("Ticket saved.", "ok");
      await loadTicket();
    } catch (error) {
      setMessage(error.message || "Failed to save ticket", "error");
    } finally {
      saveTicketBtn.disabled = false;
    }
  }

  async function addComment() {
    const body = (commentBodyInput.value || "").trim();
    const author = (commentAuthorInput.value || "analyst").trim() || "analyst";

    if (!body) {
      setMessage("Comment body is required.", "error");
      return;
    }

    addCommentBtn.disabled = true;
    setMessage("Adding comment...", "");

    try {
      const response = await fetch(`/api/tickets/${ticketId}/comments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ author, body }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Failed to add comment");
      }

      commentBodyInput.value = "";
      setMessage("Comment added.", "ok");
      await loadTicket();
    } catch (error) {
      setMessage(error.message || "Failed to add comment", "error");
    } finally {
      addCommentBtn.disabled = false;
    }
  }

  function buildTemplate(templateName) {
    const key = state.ticket ? state.ticket.ticket_key : "SOC-XXXX";

    if (templateName === "benign_test") {
      return {
        classification: "benign",
        verdict: "close",
        closeNote:
          `Investigation summary: activity appears benign/authorized testing for ${key}.\n` +
          "Evidence reviewed: SIEM timeline, process lineage, and IOC enrichment with no malicious follow-on behavior identified.\n" +
          "Disposition: closed as benign test activity with no further action required.",
      };
    }

    if (templateName === "suspicious_monitor") {
      return {
        classification: "suspicious",
        verdict: "monitor",
        closeNote:
          `Investigation summary: suspicious activity retained for monitoring on ${key}.\n` +
          "Evidence reviewed: baseline SIEM pivots and enrichment indicate elevated risk but not enough for confirmed malicious verdict.\n" +
          "Disposition: continue monitoring and keep watchlist indicators active.",
      };
    }

    return {
      classification: "malicious",
      verdict: "escalate_to_ir",
      closeNote:
        `Investigation summary: malicious indicators confirmed for ${key}.\n` +
        "Evidence reviewed: corroborating telemetry and IOC context support active threat hypothesis.\n" +
        "Disposition: escalated to Incident Response for containment and eradication.",
    };
  }

  function applyTemplate(templateName) {
    const template = buildTemplate(templateName);
    classificationSelect.value = template.classification;
    verdictSelect.value = template.verdict;
    closeNoteInput.value = template.closeNote;
    setMessage("Template applied. Review and save.", "ok");
  }

  function bindEvents() {
    saveTicketBtn.addEventListener("click", saveTicket);
    addCommentBtn.addEventListener("click", addComment);

    commentBodyInput.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
        addComment();
      }
    });

    templateButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const templateName = button.getAttribute("data-template") || "";
        applyTemplate(templateName);
      });
    });
  }

  bindEvents();
  loadTicket();
  window.setInterval(loadTicket, 12000);

  window.addEventListener("error", (event) => {
    const message = event && event.message ? event.message : "Unexpected case page error.";
    setFatalError(message);
  });
})();
