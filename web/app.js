let allProfiles = [];
let selectedProfiles = new Set();
let timeSeriesChart = null;
let currentBundleMetadata = null;

async function fetchBundles() {
  const res = await fetch('/api/bundles');
  const bundles = await res.json();
  
  // Display metadata from the first bundle (or most recent if multiple)
  if (bundles.length > 0) {
    const primaryBundle = bundles[0];
    displayBundleMetadata(primaryBundle);
  }
  
  // Collect all profiles for comparison selector
  allProfiles = [];
  bundles.forEach(b => {
    b.profiles.forEach(p => {
      allProfiles.push({
        ...p,
        bundleName: b.name,
        bundleId: b.id,
        bundleCreated: b.created
      });
    });
  });
  
  renderBundles(bundles);
  updateComparisonPanel();
  updateTimeSeriesButton();
}

function displayBundleMetadata(bundle) {
  const panel = document.getElementById('metadata-panel');
  if (!bundle.metadata) {
    panel.classList.add('hidden');
    return;
  }
  
  panel.classList.remove('hidden');
  const metadata = bundle.metadata;
  currentBundleMetadata = metadata;
  
  // Display deployment ID
  const deploymentEl = document.getElementById('deployment-id');
  if (metadata.deploymentId) {
    deploymentEl.textContent = metadata.deploymentId;
    deploymentEl.className = 'metadata-value';
    deploymentEl.title = metadata.deploymentId;
  } else {
    deploymentEl.textContent = 'Not found';
    deploymentEl.className = 'metadata-value muted';
    deploymentEl.removeAttribute('title');
  }
  
  // Display version
  const versionEl = document.getElementById('version');
  if (metadata.version) {
    versionEl.textContent = metadata.version;
    versionEl.className = 'metadata-value';
    versionEl.title = metadata.version;
  } else {
    versionEl.textContent = 'Not found';
    versionEl.className = 'metadata-value muted';
    versionEl.removeAttribute('title');
  }
  
  // Display dashboard URL
  const dashboardEl = document.getElementById('dashboard-url');
  if (metadata.dashboardUrl) {
    dashboardEl.innerHTML = `<a href="${metadata.dashboardUrl}" target="_blank">${metadata.dashboardUrl}</a>`;
    dashboardEl.className = 'metadata-value';
    dashboardEl.title = metadata.dashboardUrl;
  } else {
    dashboardEl.textContent = 'Not found';
    dashboardEl.className = 'metadata-value muted';
    dashboardEl.removeAttribute('title');
  }
  
  // Display license status
  const licenseEl = document.getElementById('license-status');
  const detailsEl = document.getElementById('license-details');
  const alertEl = document.getElementById('license-alert');
  const licenseJsonEl = document.getElementById('license-json');
  const hasLicenseData = Boolean(metadata.licenseStatusRaw) || Boolean(metadata.licenseStatus) || Boolean(metadata.tailnetBuildInfo) || Boolean(metadata.buildInfo);

  const parseMaybeJSON = (value) => {
    if (value === null || value === undefined) return null;
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed) return null;
      try {
        return JSON.parse(trimmed);
      } catch (err) {
        return trimmed;
      }
    }
    return value;
  };

  if (metadata.licenseFound) {
    if (metadata.licenseValid) {
      licenseEl.innerHTML = '<span class="license-badge license-valid">✅ Valid License</span>';
    } else {
      licenseEl.innerHTML = '<span class="license-badge license-invalid">❌ Invalid License</span>';
    }
  } else {
    licenseEl.innerHTML = '<span class="license-badge license-missing">⚠️ No License Found</span>';
  }

  const renderLicenseSections = () => {
    if (!licenseJsonEl) return;
    licenseJsonEl.innerHTML = '';

    const addSection = (label, raw, options = {}) => {
      if (raw === null || raw === undefined) return;
      const parsed = options.rawOnly ? raw : parseMaybeJSON(raw);
      if (parsed === null || parsed === undefined) return;

      const section = document.createElement('div');
      section.className = 'license-section';

      const title = document.createElement('div');
      title.className = 'license-section-title';
      title.textContent = label;

      const pre = document.createElement('pre');
      if (options.rawOnly || typeof parsed === 'string') {
        pre.textContent = options.rawOnly ? raw : parsed;
      } else {
        pre.textContent = JSON.stringify(parsed, null, 2);
      }

      section.append(title, pre);
      licenseJsonEl.appendChild(section);
    };

    const addInlineStatus = (message, variant) => {
      if (!message) return;
      const status = document.createElement('div');
      status.className = `license-inline ${variant}`;
      status.innerHTML = message;
      licenseJsonEl.appendChild(status);
    };

    addSection('license-status.txt', metadata.licenseStatusRaw || metadata.licenseStatus, { rawOnly: Boolean(metadata.licenseStatusRaw) });

    if (metadata.licenseMismatch) {
      addInlineStatus(`<span class="alert-icon">⚠️</span> ${metadata.licenseMismatch}`, 'warning');
    } else if (metadata.licenseMatch) {
      addInlineStatus('<span class="alert-icon">✅</span> License data matches between license-status.txt and tailnet_debug.html', 'success');
    }

    if (metadata.buildInfoMismatch) {
      addInlineStatus(`<span class="alert-icon">⚠️</span> ${metadata.buildInfoMismatch}`, 'warning');
    } else if (metadata.buildInfoMatch) {
      addInlineStatus('<span class="alert-icon">✅</span> tailnet_debug.html trace matches deployment/buildinfo.json', 'success');
    }

    addSection('deployment/buildinfo.json', metadata.buildInfo);
    addSection('tailnet_debug.html trace (build info)', metadata.tailnetBuildInfo);

    if (!licenseJsonEl.children.length) {
      const empty = document.createElement('div');
      empty.className = 'muted';
      empty.textContent = 'No bundle metadata details available.';
      licenseJsonEl.appendChild(empty);
    }
  };
  if (alertEl) {
    const messages = [];
    if (metadata.licenseMismatch) {
      messages.push(`<span class="alert-icon">⚠️</span> ${metadata.licenseMismatch}`);
    }
    if (metadata.buildInfoMismatch) {
      messages.push(`<span class="alert-icon">⚠️</span> ${metadata.buildInfoMismatch}`);
    }

    if (messages.length > 0) {
      alertEl.className = 'license-alert warning';
      alertEl.innerHTML = messages.join('<br>');
    } else {
      alertEl.className = 'license-alert hidden';
      alertEl.textContent = '';
    }
  }
  if (detailsEl) {
    detailsEl.classList.toggle('hidden', !hasLicenseData);
  }
  renderLicenseSections();
}

function updateTimeSeriesButton() {
  const btn = document.getElementById('timeseries-btn');
  if (btn) {
    btn.style.display = allProfiles.length > 1 ? 'inline-block' : 'none';
  }
}

function renderBundles(bundles) {
  const container = document.getElementById('bundles');
  container.innerHTML = '';
  for (const b of bundles) {
    const el = document.getElementById('bundle-tpl').content.firstElementChild.cloneNode(true);
    el.querySelector('h2').textContent = b.name + ' — ' + new Date(b.created).toLocaleString();
    
    // Add metadata summary
    let metaText = `${b.profiles.length} profiles`;
    if (b.metadata && b.metadata.version) {
      metaText += ` | Version: ${b.metadata.version}`;
    }
    el.querySelector('.meta').textContent = metaText;
    
    // Show warnings if any (including license warnings)
    const allWarnings = [...(b.warnings || [])];
    if (b.metadata && b.metadata.licenseMismatch) {
      allWarnings.push(b.metadata.licenseMismatch);
    }
    if (b.metadata && b.metadata.buildInfoMismatch) {
      allWarnings.push(b.metadata.buildInfoMismatch);
    }
    
    if (allWarnings.length > 0) {
      const warnings = document.createElement('div');
      warnings.className = 'warnings';
      warnings.innerHTML = `<span class="warning-icon">⚠️</span> ${allWarnings.length} warning(s)`;
      warnings.title = allWarnings.join('\n');
      el.querySelector('.meta').appendChild(warnings);
    }
    
    const pwrap = el.querySelector('.profiles');
    for (const p of b.profiles) {
      const pEl = renderProfile(p, b.id);
      pwrap.appendChild(pEl);
    }
    container.appendChild(el);
  }
}

function renderProfile(p, bundleId) {
  const el = document.getElementById('profile-tpl').content.firstElementChild.cloneNode(true);
  el.dataset.profileId = p.id;
  el.dataset.bundleId = bundleId;
  
  el.querySelector('.title').textContent = p.name;
  el.querySelector('.tags').textContent = `${p.sampleTypes.join(', ')} | samples: ${p.sampleCount} | funcs: ${p.functionCount} | duration: ${p.durationSec?.toFixed(2) ?? 0}s`;
  el.querySelector('.download').href = `/api/profiles/${p.id}/raw`;
  
  // Checkbox for comparison
  const checkbox = el.querySelector('.compare-checkbox');
  checkbox.addEventListener('change', (e) => {
    if (e.target.checked) {
      selectedProfiles.add(p.id);
    } else {
      selectedProfiles.delete(p.id);
    }
    updateComparisonPanel();
  });
  
  // Keep href for copyability, but prevent default so current tab doesn't navigate.
  const pprofLink = el.querySelector('.pprof');
  pprofLink.href = `/pprof/${p.id}/ui`;
  pprofLink.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    window.open(pprofLink.href, '_blank', 'noopener,noreferrer');
    return false;
  });

  el.querySelector('.show-top').addEventListener('click', async () => {
    await showTop(el, p.id);
  });
  
  el.querySelector('.show-flame').addEventListener('click', async () => {
    await showFlame(el, p.id);
  });
  
  el.querySelector('.show-search').addEventListener('click', async () => {
    await showSearch(el, p.id);
  });
  
  // Export dropdown
  el.querySelector('.export-csv').addEventListener('click', () => {
    window.open(`/api/profiles/${p.id}/raw?format=csv`, '_blank');
  });
  
  el.querySelector('.export-json').addEventListener('click', () => {
    window.open(`/api/profiles/${p.id}/raw?format=json`, '_blank');
  });
  
  el.querySelector('.export-raw').addEventListener('click', () => {
    window.open(`/api/profiles/${p.id}/raw`, '_blank');
  });
  
  return el;
}

function updateComparisonPanel() {
  const panel = document.getElementById('comparison-panel');
  const btn = document.getElementById('compare-btn');
  const list = document.getElementById('selected-profiles-list');
  
  if (selectedProfiles.size === 0) {
    panel.classList.add('hidden');
    return;
  }
  
  panel.classList.remove('hidden');
  btn.disabled = selectedProfiles.size !== 2;
  
  if (selectedProfiles.size === 2) {
    btn.textContent = 'Compare Selected Profiles';
    btn.classList.remove('disabled');
  } else {
    btn.textContent = `Select ${2 - selectedProfiles.size} more profile(s) to compare`;
    btn.classList.add('disabled');
  }
  
  // Update selected list
  list.innerHTML = '';
  selectedProfiles.forEach(id => {
    const profile = allProfiles.find(p => p.id === id);
    if (profile) {
      const item = document.createElement('div');
      item.className = 'selected-profile-item';
      item.innerHTML = `
        <span>${profile.bundleName} / ${profile.name}</span>
        <button class="remove-btn" data-id="${id}">×</button>
      `;
      item.querySelector('.remove-btn').addEventListener('click', () => {
        selectedProfiles.delete(id);
        document.querySelector(`[data-profile-id="${id}"] .compare-checkbox`).checked = false;
        updateComparisonPanel();
      });
      list.appendChild(item);
    }
  });
}

async function compareProfiles() {
  const ids = Array.from(selectedProfiles);
  if (ids.length !== 2) return;
  
  const modal = document.getElementById('comparison-modal');
  const results = document.getElementById('comparison-results');
  
  modal.classList.remove('hidden');
  results.innerHTML = '<div class="loading">Loading comparison...</div>';
  
  try {
    // Fetch both table comparison and flame diff
    const [compRes, flameRes] = await Promise.all([
      fetch(`/api/profiles/compare?p1=${ids[0]}&p2=${ids[1]}`),
      fetch(`/api/profiles/flamediff?p1=${ids[0]}&p2=${ids[1]}`)
    ]);
    
    if (!compRes.ok || !flameRes.ok) {
      throw new Error(`HTTP error`);
    }
    
    const compData = await compRes.json();
    const flameData = await flameRes.json();
    
    renderComparison(compData, flameData);
  } catch (error) {
    results.innerHTML = `<div class="error">Failed to compare profiles: ${error.message}</div>`;
  }
}

function renderComparison(data, flameData) {
  const results = document.getElementById('comparison-results');
  
  const html = `
    <div class="comparison-header">
      <h3>Comparing: ${data.profile1} vs ${data.profile2}</h3>
      <div class="comparison-tabs">
        <button class="tab-btn active" data-tab="table">Table View</button>
        <button class="tab-btn" data-tab="flame">Flame Diff</button>
      </div>
      <div class="legend">
        <span class="legend-item"><span class="increased">▲</span> Increased</span>
        <span class="legend-item"><span class="decreased">▼</span> Decreased</span>
        <span class="legend-item"><span class="unchanged">—</span> Unchanged</span>
      </div>
    </div>
    
    <div class="tab-content active" data-tab="table">
      <div class="comparison-table-container">
        <table class="comparison-table">
          <thead>
            <tr>
              <th>Function</th>
              <th>Profile 1</th>
              <th>Profile 2</th>
              <th>Diff</th>
              <th>Change %</th>
            </tr>
          </thead>
          <tbody>
            ${data.diff.slice(0, 100).map(row => {
              const changeClass = row.flatDiff > 0 ? 'increased' : row.flatDiff < 0 ? 'decreased' : 'unchanged';
              const icon = row.flatDiff > 0 ? '▲' : row.flatDiff < 0 ? '▼' : '—';
              return `
                <tr class="${changeClass}">
                  <td class="func-name" title="${row.func}">${truncate(row.func, 60)}</td>
                  <td class="numeric">${row.flat1.toLocaleString()}</td>
                  <td class="numeric">${row.flat2.toLocaleString()}</td>
                  <td class="numeric diff">
                    <span class="${changeClass}">
                      ${icon} ${Math.abs(row.flatDiff).toLocaleString()}
                    </span>
                  </td>
                  <td class="numeric">
                    ${row.pctDiff !== 0 ? `${row.pctDiff > 0 ? '+' : ''}${row.pctDiff.toFixed(2)}%` : '—'}
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    </div>
    
    <div class="tab-content" data-tab="flame">
      <div class="flame-diff-controls">
        <label><input type="radio" name="flame-mode" value="diff" checked> Show Difference</label>
        <label><input type="radio" name="flame-mode" value="profile1"> Profile 1 Only</label>
        <label><input type="radio" name="flame-mode" value="profile2"> Profile 2 Only</label>
      </div>
      <canvas id="flame-diff-canvas" width="1400" height="500"></canvas>
    </div>
  `;
  
  results.innerHTML = html;
  
  // Setup tab switching
  const tabBtns = results.querySelectorAll('.tab-btn');
  const tabContents = results.querySelectorAll('.tab-content');
  
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      tabContents.forEach(content => {
        content.classList.toggle('active', content.dataset.tab === tabName);
      });
      
      if (tabName === 'flame') {
        drawFlameDiff(document.getElementById('flame-diff-canvas'), flameData);
      }
    });
  });
  
  // Setup flame mode switching
  const modeRadios = results.querySelectorAll('input[name="flame-mode"]');
  modeRadios.forEach(radio => {
    radio.addEventListener('change', () => {
      drawFlameDiff(document.getElementById('flame-diff-canvas'), flameData, radio.value);
    });
  });
}

function drawFlameDiff(canvas, tree, mode = 'diff') {
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  
  const levels = [];
  function traverse(n, depth) {
    if (!levels[depth]) levels[depth] = [];
    levels[depth].push(n);
    (n.children || []).forEach(c => traverse(c, depth + 1));
  }
  traverse(tree, 0);
  
  const maxDepth = levels.length;
  const total1 = (tree.children || []).reduce((acc, c) => acc + c.value1, 0) || 1;
  const total2 = (tree.children || []).reduce((acc, c) => acc + c.value2, 0) || 1;
  const total = mode === 'profile2' ? total2 : total1;
  
  function layout(n, x0, x1, depth) {
    n._x0 = x0; n._x1 = x1; n._depth = depth;
    const children = n.children || [];
    const value = mode === 'profile2' ? n.value2 : n.value1;
    let sum = children.reduce((a, c) => {
      const v = mode === 'profile2' ? c.value2 : c.value1;
      return a + v;
    }, 0);
    
    if (sum <= 0) return;
    let x = x0;
    for (const c of children) {
      const cv = mode === 'profile2' ? c.value2 : c.value1;
      const w = (x1 - x0) * (cv / sum);
      layout(c, x, x + w, depth + 1);
      x += w;
    }
  }
  
  layout({children: tree.children}, 0, W, 0);
  
  const barH = Math.max(14, Math.floor(H / (maxDepth + 1)));
  const regions = [];
  
  function pickDiffColor(node) {
    if (mode === 'diff') {
      if (node.diff > 0) {
        const intensity = Math.min(255, Math.abs(node.pctDiff) * 2);
        return `rgb(${intensity}, 0, 0)`;
      } else if (node.diff < 0) {
        const intensity = Math.min(255, Math.abs(node.pctDiff) * 2);
        return `rgb(0, ${intensity}, 0)`;
      } else {
        return `rgb(128, 128, 128)`;
      }
    }
    return pickColor(node.name);
  }
  
  function drawNode(n, depth) {
    if (!n.children) return;
    for (const c of n.children) {
      if (c._x0 === undefined) continue;
      
      const x = c._x0, w = Math.max(0.5, c._x1 - c._x0), y = depth * barH;
      ctx.fillStyle = pickDiffColor(c);
      ctx.fillRect(x, y, w, barH - 2);
      ctx.strokeStyle = '#0b0d12';
      ctx.strokeRect(x + 0.25, y + 0.25, w - 0.5, barH - 2.5);
      
      if (w > 80) {
        ctx.fillStyle = '#ffffff';
        ctx.font = '11px system-ui, sans-serif';
        const value = mode === 'profile2' ? c.value2 : mode === 'profile1' ? c.value1 : c.diff;
        const label = mode === 'diff' && c.diff !== 0
          ? `${c.name} (${c.diff > 0 ? '+' : ''}${c.diff})`
          : `${c.name} (${value})`;
        ctx.fillText(label, x + 4, y + barH - 6);
      }
      
      regions.push({
        x, y, w, h: barH - 2, 
        node: c, 
        depth,
        mode
      });
      drawNode(c, depth + 1);
    }
  }
  
  drawNode({children: tree.children}, 0);
  
  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    
    for (const r of regions) {
      if (x >= r.x && x <= r.x + r.w && y >= r.y && y <= r.y + r.h) {
        const tip = ensureTip();
        tip.style.display = 'block';
        tip.style.left = (e.clientX + 10) + 'px';
        tip.style.top = (e.clientY + 10) + 'px';
        
        const content = r.mode === 'diff' 
          ? `${r.node.name}
Profile 1: ${r.node.value1}
Profile 2: ${r.node.value2}
Diff: ${r.node.diff > 0 ? '+' : ''}${r.node.diff} (${r.node.pctDiff > 0 ? '+' : ''}${r.node.pctDiff.toFixed(1)}%)`
          : `${r.node.name}
Value: ${r.mode === 'profile2' ? r.node.value2 : r.node.value1}`;
        
        tip.innerHTML = content.replace(/\n/g, '<br>');
        return;
      }
    }
    ensureTip().style.display = 'none';
  };
  
  canvas.onmouseleave = () => ensureTip().style.display = 'none';
}

async function showTimeSeries() {
  const modal = document.getElementById('timeseries-modal');
  const content = document.getElementById('timeseries-content');
  
  modal.classList.remove('hidden');
  content.innerHTML = `
    <div class="timeseries-controls">
      <input type="text" id="function-filter" placeholder="Filter by function name (optional)">
      <button onclick="loadTimeSeries()">Load Data</button>
    </div>
    <div id="timeseries-chart-container">
      <canvas id="timeseries-chart" width="1200" height="400"></canvas>
    </div>
    <div id="timeseries-legend"></div>
  `;
}

async function loadTimeSeries() {
  const filter = document.getElementById('function-filter').value;
  const container = document.getElementById('timeseries-chart-container');
  
  try {
    const res = await fetch(`/api/profiles/timeseries?function=${encodeURIComponent(filter)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    
    const data = await res.json();
    
    if (data.length === 0) {
      container.innerHTML = '<div class="muted">No data points found</div>';
      return;
    }
    
    drawTimeSeriesChart(data);
  } catch (error) {
    container.innerHTML = `<div class="error">Failed to load time series: ${error.message}</div>`;
  }
}

function drawTimeSeriesChart(data) {
  const canvas = document.getElementById('timeseries-chart');
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const padding = { top: 20, right: 20, bottom: 60, left: 80 };
  
  ctx.clearRect(0, 0, W, H);
  
  // Group by metric type
  const metricTypes = new Set();
  data.forEach(d => Object.keys(d.metrics).forEach(k => metricTypes.add(k)));
  
  const colors = ['#6ea8fe', '#7ee787', '#ef4444', '#f59e0b', '#a78bfa', '#ec4899'];
  const metricColors = {};
  Array.from(metricTypes).forEach((m, i) => {
    metricColors[m] = colors[i % colors.length];
  });
  
  // Find min/max values
  let minTime = new Date(data[0].timestamp);
  let maxTime = new Date(data[data.length - 1].timestamp);
  let maxValue = 0;
  
  data.forEach(d => {
    Object.values(d.metrics).forEach(v => {
      if (v > maxValue) maxValue = v;
    });
  });
  
  // Scale functions
  const xScale = (time) => {
    const t = new Date(time).getTime();
    const range = maxTime.getTime() - minTime.getTime();
    return padding.left + ((t - minTime.getTime()) / range) * (W - padding.left - padding.right);
  };
  
  const yScale = (value) => {
    return H - padding.bottom - (value / maxValue) * (H - padding.top - padding.bottom);
  };
  
  // Draw axes
  ctx.strokeStyle = '#9aa4b2';
  ctx.lineWidth = 1;
  
  // Y-axis
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, H - padding.bottom);
  ctx.stroke();
  
  // X-axis
  ctx.beginPath();
  ctx.moveTo(padding.left, H - padding.bottom);
  ctx.lineTo(W - padding.right, H - padding.bottom);
  ctx.stroke();
  
  // Draw grid lines and labels
  ctx.fillStyle = '#9aa4b2';
  ctx.font = '11px system-ui, sans-serif';
  ctx.textAlign = 'right';
  
  for (let i = 0; i <= 5; i++) {
    const value = (maxValue / 5) * i;
    const y = yScale(value);
    
    ctx.strokeStyle = '#1c2130';
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(W - padding.right, y);
    ctx.stroke();
    
    ctx.fillStyle = '#9aa4b2';
    ctx.fillText(formatValue(value), padding.left - 5, y + 3);
  }
  
  // Draw time labels
  ctx.textAlign = 'center';
  data.forEach((d, i) => {
    if (i % Math.ceil(data.length / 5) === 0) {
      const x = xScale(d.timestamp);
      const time = new Date(d.timestamp);
      ctx.fillText(time.toLocaleDateString() + '\n' + time.toLocaleTimeString(), x, H - padding.bottom + 20);
    }
  });
  
  // Draw lines for each metric
  Object.keys(metricColors).forEach(metric => {
    const points = data.filter(d => d.metrics[metric]).map(d => ({
      x: xScale(d.timestamp),
      y: yScale(d.metrics[metric]),
      value: d.metrics[metric],
      name: d.name,
      timestamp: d.timestamp
    }));
    
    if (points.length === 0) return;
    
    ctx.strokeStyle = metricColors[metric];
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    
    points.forEach((p, i) => {
      if (i > 0) ctx.lineTo(p.x, p.y);
    });
    ctx.stroke();
    
    // Draw points
    ctx.fillStyle = metricColors[metric];
    points.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
      ctx.fill();
    });
  });
  
  // Update legend
  const legend = document.getElementById('timeseries-legend');
  legend.innerHTML = `
    <div class="legend-items">
      ${Object.entries(metricColors).map(([metric, color]) => `
        <span class="legend-item">
          <span class="legend-color" style="background: ${color}"></span>
          ${metric}
        </span>
      `).join('')}
    </div>
  `;
}

function formatValue(v) {
  if (v > 1e9) return (v / 1e9).toFixed(1) + 'B';
  if (v > 1e6) return (v / 1e6).toFixed(1) + 'M';
  if (v > 1e3) return (v / 1e3).toFixed(1) + 'K';
  return v.toFixed(0);
}

function truncate(str, len) {
  if (str.length <= len) return str;
  return str.substring(0, len - 3) + '...';
}

async function showSearch(root, pid) {
  const panel = root.querySelector('.panel.search');
  const other1 = root.querySelector('.panel.top');
  const other2 = root.querySelector('.panel.flame');
  other1.classList.add('hidden');
  other2.classList.add('hidden');
  
  if (!panel.querySelector('input')) {
    panel.innerHTML = `
      <div class="search-box">
        <input type="text" placeholder="Filter functions by name..." class="search-input">
        <button class="search-btn">Search</button>
      </div>
      <div class="search-results"></div>
    `;
    
    const input = panel.querySelector('.search-input');
    const btn = panel.querySelector('.search-btn');
    const results = panel.querySelector('.search-results');
    
    const doSearch = async () => {
      const query = input.value.trim();
      if (!query) {
        results.innerHTML = '<div class="muted">Enter a search term</div>';
        return;
      }
      
      const res = await fetch(`/api/profiles/${pid}/top?filter=${encodeURIComponent(query)}`);
      const rows = await res.json();
      
      if (rows.length === 0) {
        results.innerHTML = '<div class="muted">No matching functions found</div>';
        return;
      }
      
      results.innerHTML = `
        <table class="top-table">
          <thead>
            <tr>
              <th>Function</th>
              <th>File</th>
              <th>Flat</th>
              <th>Flat%</th>
              <th>Cum</th>
              <th>Cum%</th>
            </tr>
          </thead>
          <tbody>
            ${rows.slice(0, 100).map(r => `
              <tr>
                <td>${r.func}</td>
                <td>${r.file || ''}</td>
                <td>${r.flat}</td>
                <td>${r.flatPct.toFixed(2)}%</td>
                <td>${r.cum}</td>
                <td>${r.cumPct.toFixed(2)}%</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      `;
    };
    
    btn.addEventListener('click', doSearch);
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') doSearch();
    });
  }
  
  panel.classList.remove('hidden');
}

async function showTop(root, pid) {
  const panel = root.querySelector('.panel.top');
  const other1 = root.querySelector('.panel.flame');
  const other2 = root.querySelector('.panel.search');
  other1.classList.add('hidden');
  other2.classList.add('hidden');
  
  const res = await fetch(`/api/profiles/${pid}/top`);
  const rows = await res.json();
  const tbody = panel.querySelector('tbody');
  tbody.innerHTML = '';
  for (const r of rows.slice(0, 100)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${r.func}</td><td>${r.file||''}</td><td>${r.flat}</td><td>${r.flatPct.toFixed(2)}%</td><td>${r.cum}</td><td>${r.cumPct.toFixed(2)}%</td>`;
    tbody.appendChild(tr);
  }
  panel.classList.remove('hidden');
}

async function showFlame(root, pid) {
  const panel = root.querySelector('.panel.flame');
  const other1 = root.querySelector('.panel.top');
  const other2 = root.querySelector('.panel.search');
  other1.classList.add('hidden');
  other2.classList.add('hidden');
  
  const res = await fetch(`/api/profiles/${pid}/flame`);
  const tree = await res.json();
  drawFlame(panel.querySelector('.flamecanvas'), tree);
  panel.classList.remove('hidden');
}

function drawFlame(canvas, tree) {
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0,0,W,H);

  const levels = [];
  function traverse(n, depth) {
    if (!levels[depth]) levels[depth] = [];
    levels[depth].push(n);
    (n.children||[]).forEach(c => traverse(c, depth+1));
  }
  traverse(tree, 0);
  const maxDepth = levels.length;
  const total = (tree.children||[]).reduce((acc, c)=>acc + c.value, 0) || 1;

  function layout(n, x0, x1, depth) {
    n._x0 = x0; n._x1 = x1; n._depth = depth;
    const children = n.children || [];
    let sum = children.reduce((a,c)=>a+c.value, 0);
    if (sum <= 0) return;
    let x = x0;
    for (const c of children) {
      const w = (x1-x0) * (c.value / sum);
      layout(c, x, x+w, depth+1);
      x += w;
    }
  }
  layout({children: tree.children}, 0, W, 0);

  const barH = Math.max(14, Math.floor(H / (maxDepth+1)));
  const tip = ensureTip();
  const regions = [];

  function drawNode(n, depth) {
    if (!n.children) return;
    for (const c of n.children) {
      const x = c._x0, w = Math.max(0.5, c._x1 - c._x0), y = depth * barH;
      ctx.fillStyle = pickColor(c.name);
      ctx.fillRect(x, y, w, barH-2);
      ctx.strokeStyle = '#0b0d12';
      ctx.strokeRect(x+0.25, y+0.25, w-0.5, barH-2.5);
      if (w > 60) {
        ctx.fillStyle = '#0b0d12';
        ctx.font = '12px system-ui, sans-serif';
        const label = `${c.name} (${fmtPct(c.value, total)})`;
        ctx.fillText(label, x+4, y+barH-6);
      }
      regions.push({x, y, w, h: barH-2, node: c, depth});
      drawNode(c, depth+1);
    }
  }
  drawNode({children: tree.children}, 0);

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    for (const r of regions) {
      if (x>=r.x && x<=r.x+r.w && y>=r.y && y<=r.y+r.h) {
        const tip = ensureTip();
        tip.style.display = 'block';
        tip.style.left = (e.clientX+10)+'px';
        tip.style.top = (e.clientY+10)+'px';
        tip.textContent = `${r.node.name} • ${fmtPct(r.node.value, total)} (${r.node.value})`;
        return;
      }
    }
    ensureTip().style.display = 'none';
  };
  canvas.onmouseleave = ()=> ensureTip().style.display = 'none';
}

function fmtPct(v, total) {
  return ((v*100/(total||1)).toFixed(2)) + '%';
}

function ensureTip() {
  let el = document.querySelector('.flame-tip');
  if (!el) {
    el = document.createElement('div');
    el.className = 'flame-tip';
    document.body.appendChild(el);
  }
  return el;
}

function pickColor(s) {
  let h=0; for (let i=0;i<s.length;i++){ h = (h*31 + s.charCodeAt(i))>>>0; }
  const r = (h & 0xFF), g = (h>>>8) & 0xFF, b = (h>>>16)&0xFF;
  return `rgb(${(r%128)+64},${(g%128)+64},${(b%128)+64})`;
}

// Make loadTimeSeries globally accessible
window.loadTimeSeries = loadTimeSeries;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  // Setup comparison panel
  document.getElementById('compare-btn').addEventListener('click', compareProfiles);
  document.getElementById('close-modal').addEventListener('click', () => {
    document.getElementById('comparison-modal').classList.add('hidden');
  });
  
  // Setup time series modal
  document.getElementById('timeseries-btn')?.addEventListener('click', showTimeSeries);
  document.getElementById('close-timeseries')?.addEventListener('click', () => {
    document.getElementById('timeseries-modal').classList.add('hidden');
  });
  
  // Close modals on background click
  document.getElementById('comparison-modal').addEventListener('click', (e) => {
    if (e.target.id === 'comparison-modal') {
      document.getElementById('comparison-modal').classList.add('hidden');
    }
  });
  
  document.getElementById('timeseries-modal')?.addEventListener('click', (e) => {
    if (e.target.id === 'timeseries-modal') {
      document.getElementById('timeseries-modal').classList.add('hidden');
    }
  });
  
  // Upload functionality
  const uploadBtn = document.getElementById('upload-btn');
  const uploadInput = document.getElementById('upload-input');
  
  if (uploadBtn && uploadInput) {
    uploadBtn.addEventListener('click', () => uploadInput.click());
    
    uploadInput.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      
      const formData = new FormData();
      formData.append('bundle', file);
      
      uploadBtn.disabled = true;
      uploadBtn.textContent = 'Uploading...';
      
      try {
        const res = await fetch('/api/bundles', {
          method: 'POST',
          body: formData
        });
        
        if (!res.ok) {
          const text = await res.text();
          throw new Error(text || `HTTP ${res.status}`);
        }
        
        const result = await res.json();
        
        if (result.warnings && result.warnings.length > 0) {
          alert(`Bundle uploaded with warnings:\n${result.warnings.join('\n')}`);
        }
        
        // Reload bundles
        await fetchBundles();
      } catch (error) {
        alert(`Upload failed: ${error.message}`);
      } finally {
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload Bundle';
        uploadInput.value = '';
      }
    });
  }
  
  fetchBundles().catch(console.error);
});
