async function fetchBundles() {
  const res = await fetch('/api/bundles');
  const bundles = await res.json();
  renderBundles(bundles);
}

function renderBundles(bundles) {
  const container = document.getElementById('bundles');
  container.innerHTML = '';
  for (const b of bundles) {
    const el = document.getElementById('bundle-tpl').content.firstElementChild.cloneNode(true);
    el.querySelector('h2').textContent = b.name + ' — ' + new Date(b.created).toLocaleString();
    el.querySelector('.meta').textContent = `${b.profiles.length} profiles`;
    const pwrap = el.querySelector('.profiles');
    for (const p of b.profiles) {
      const pEl = renderProfile(p);
      pwrap.appendChild(pEl);
    }
    container.appendChild(el);
  }
}

function renderProfile(p) {
  const el = document.getElementById('profile-tpl').content.firstElementChild.cloneNode(true);
  el.querySelector('.title').textContent = p.name;
  el.querySelector('.tags').textContent = `${p.sampleTypes.join(', ')} | samples: ${p.sampleCount} | funcs: ${p.functionCount} | duration: ${p.durationSec?.toFixed(2) ?? 0}s`;
  el.querySelector('.download').href = `/api/profiles/${p.id}/raw`;
  // Keep href for copyability, but prevent default so current tab doesn't navigate.
  const pprofLink = el.querySelector('.pprof');
  pprofLink.href = `/pprof/${p.id}/ui`;
  pprofLink.target = "_blank";
  pprofLink.rel = "noopener noreferrer";


  el.querySelector('.show-top').addEventListener('click', async () => {
    await showTop(el, p.id);
  });
  el.querySelector('.show-flame').addEventListener('click', async () => {
    await showFlame(el, p.id);
  });
  return el;
}

async function showTop(root, pid) {
  const panel = root.querySelector('.panel.top');
  const other = root.querySelector('.panel.flame'); other.classList.add('hidden');
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
  const other = root.querySelector('.panel.top'); other.classList.add('hidden');
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

fetchBundles().catch(console.error);
