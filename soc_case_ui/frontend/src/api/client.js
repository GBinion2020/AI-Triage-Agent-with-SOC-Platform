const JSON_HEADERS = { 'Content-Type': 'application/json' };

async function request(path, options = {}) {
  const response = await fetch(path, {
    cache: 'no-store',
    ...options,
    headers: {
      ...(options.headers || {}),
    },
  });

  let data;
  const text = await response.text();
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_error) {
    data = { detail: text || 'Invalid response payload' };
  }

  if (!response.ok) {
    throw new Error(data?.detail || `Request failed (${response.status})`);
  }

  return data;
}

export const api = {
  getTickets({ status = 'all', q = '' } = {}) {
    return request(`/api/tickets?status=${encodeURIComponent(status)}&q=${encodeURIComponent(q)}`);
  },

  getTicket(ticketId) {
    return request(`/api/tickets/${ticketId}`);
  },

  updateTicket(ticketId, payload) {
    return request(`/api/tickets/${ticketId}`, {
      method: 'PATCH',
      headers: JSON_HEADERS,
      body: JSON.stringify(payload),
    });
  },

  addComment(ticketId, payload) {
    return request(`/api/tickets/${ticketId}/comments`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify(payload),
    });
  },

  getAudit(ticketId) {
    return request(`/api/tickets/${ticketId}/audit`);
  },

  startPipeline(payload) {
    return request('/api/pipeline/start', {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify(payload),
    });
  },

  getPipelineStatus() {
    return request('/api/pipeline/status');
  },

  getPipelineLogs(cursor = 0) {
    return request(`/api/pipeline/logs?cursor=${encodeURIComponent(cursor)}`);
  },
};

export function shortDate(value) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '-';
  }
  return date.toLocaleString();
}

export function statusLabel(raw) {
  const value = String(raw || '').toLowerCase();
  if (value === 'to_do') return 'To Do';
  if (value === 'in_progress') return 'In Progress';
  if (value === 'done') return 'Done';
  if (value === 'completed') return 'Completed';
  if (value === 'completed_no_alerts') return 'Completed (No Alerts)';
  return value || 'Unknown';
}

export function severityLabel(raw) {
  const value = String(raw || 'unknown').toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(value)) {
    return value;
  }
  return 'unknown';
}

export function numericScore(value) {
  if (value == null || value === '') {
    return null;
  }
  const number = Number(value);
  if (Number.isFinite(number)) {
    return number;
  }
  return null;
}

export function severityFromRiskScore(score, fallback = 'unknown') {
  const value = numericScore(score);
  if (value == null) {
    return severityLabel(fallback);
  }
  if (value >= 80) return 'critical';
  if (value >= 60) return 'high';
  if (value >= 40) return 'medium';
  return 'low';
}

export function normalizeToolLabel(value) {
  return String(value || '')
    .replace(/\s*\(w\d+_a\d+_[a-f0-9]+\)\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}
