const LOG_RENDER_DEFAULT_LIMIT = 2 * 1024 * 1024;
let currentBundleId = null;

function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value < 0) return '';
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let val = value;
  let unit = units[0];
  for (let i = 0; i < units.length; i++) {
    unit = units[i];
    if (val < 1024 || i === units.length - 1) break;
    val = val / 1024;
  }
  const digits = val >= 10 ? 0 : 1;
  return `${val.toFixed(digits)} ${unit}`;
}

function formatLogMeta(meta) {
  if (!meta) return '';
  const parts = [];
  const sizeLabel = formatBytes(meta.size);
  if (sizeLabel) parts.push(sizeLabel);
  if (Number.isFinite(meta.lines) && meta.lines > 0) {
    const count = Number(meta.lines);
    parts.push(`${count} line${count === 1 ? '' : 's'}`);
  }
  if (meta.truncated) {
    parts.push('truncated for display');
  }
  return parts.join(' • ');
}

async function resolveBundleId() {
  const params = new URLSearchParams(window.location.search);
  const id = params.get('bundle');
  if (id) {
    return id;
  }
  const res = await fetch('/api/bundles');
  if (!res.ok) {
    throw new Error(`Failed to list bundles (HTTP ${res.status})`);
  }
  const bundles = await res.json();
  if (!Array.isArray(bundles) || bundles.length === 0) {
    throw new Error('No bundles loaded');
  }
  return bundles[0].id;
}

async function loadLogs(force = false) {
  const body = document.getElementById('logs-page-body');
  const pathEl = document.getElementById('logs-page-path');
  const metaEl = document.getElementById('logs-page-meta');
  const reloadBtn = document.getElementById('logs-page-reload');

  if (!force && currentBundleId && body.dataset.bundleId === currentBundleId && body.dataset.loaded === 'true') {
    return;
  }

  if (reloadBtn) {
    reloadBtn.disabled = true;
    reloadBtn.textContent = 'Loading...';
  }
  body.innerHTML = '<div class="loading">Loading agent logs…</div>';

  try {
    currentBundleId = await resolveBundleId();
    const res = await fetch(`/api/bundles/${currentBundleId}/logs/agent`);
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `HTTP ${res.status}`);
    }
    const data = await res.json();
    const metaText = formatLogMeta(data);
    const limit = Number(data.limitBytes) || LOG_RENDER_DEFAULT_LIMIT;
    const truncatedNotice = data.truncated
      ? `<div class="logs-footnote">Log truncated to keep the viewer responsive (${formatBytes(limit) || 'display limit'}).</div>`
      : '';
    const html = `<div class="logs-scroll">${data.html || ''}</div>${truncatedNotice}`;

    body.innerHTML = html;
    body.dataset.bundleId = currentBundleId;
    body.dataset.loaded = 'true';

    if (pathEl) {
      pathEl.textContent = data.path || 'agent/logs.txt';
      pathEl.title = data.path || '';
    }
    if (metaEl) {
      metaEl.textContent = metaText || data.path || 'agent/logs.txt';
    }
    document.title = data.path ? `Agent Logs • ${data.path}` : 'Agent Logs';
  } catch (error) {
    body.innerHTML = `<div class="error">Failed to load logs: ${escapeHTML(error.message)}</div>`;
    if (metaEl) {
      metaEl.textContent = 'Error loading logs';
    }
  } finally {
    if (reloadBtn) {
      reloadBtn.disabled = false;
      reloadBtn.textContent = 'Reload Logs';
    }
  }
}

function escapeHTML(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

document.addEventListener('DOMContentLoaded', () => {
  loadLogs();
  document.getElementById('logs-page-reload')?.addEventListener('click', () => loadLogs(true));
});
