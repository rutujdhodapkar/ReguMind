/* ═══════════════════════════════════════════════════════════════
   Phantom Compliance - Client-side Application
   Handles navigation, data fetching, rendering, interactivity
   ═══════════════════════════════════════════════════════════════ */

(function() {
  'use strict';

  // ─── Globals ─────────────────────────────────────────────

  const PAGE = window.__PAGE__ || null;
  const ROLE = window.__INITIAL_ROLE__ || '';
  const IS_CCO = window.__IS_CCO__ || (ROLE === 'CCO');

  const DISPLAY_NAMES = {
    'CCO': 'Chief Compliance Officer',
    'KYC': 'KYC / Compliance',
    'Payments': 'Payments / IT',
    'IT_Security': 'IT Security / Audit',
    'Treasury': 'Treasury / Risk',
    'Forex': 'Forex / Treasury',
    'Credit_Risk': 'Credit / Stressed Assets'
  };

  const STATUS_CLASSES = {
    'VALIDATED': 'status-validated',
    'BREACHED': 'status-breached',
    'ESCALATED': 'status-escalated',
    'PENDING': 'status-pending',
    'ASSIGNED': 'status-assigned'
  };

  let currentTab = null;
  let blocksCache = null;

  // ─── Helpers ─────────────────────────────────────────────

  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }

  function api(url, opts) {
    return fetch(url, {
      headers: {'Content-Type': 'application/json', 'Accept': 'application/json'},
      ...opts
    }).then(r => r.json());
  }

  function html(str) {
    const t = document.createElement('template');
    t.innerHTML = str.trim();
    return t.content.firstChild;
  }

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str || '';
    return d.innerHTML;
  }

  function statusClass(s) { return STATUS_CLASSES[s] || 'status-pending'; }

  function deptName(r) { return DISPLAY_NAMES[r] || r; }

  function shortHash(h) { return h ? h.substring(0, 16) + '...' : '—'; }

  // ─── Sidebar ─────────────────────────────────────────────

  function buildSidebar() {
    const userEl = document.getElementById('sidebar-username');
    const roleEl = document.getElementById('sidebar-role');
    const navEl = document.getElementById('sidebar-nav');
    if (!navEl) return;

    api('/api/session').then(d => {
      if (userEl) userEl.textContent = d.username;
      if (roleEl) roleEl.textContent = d.role;

      let links = [];
      links.push({label: 'Dashboard', href: '/dashboard'});
      if (d.role === 'CCO') {
        links.push({label: 'CCO Dashboard', href: '/cco'});
        links.push({label: 'User Management', href: '/users'});
      } else {
        links.push({label: 'Department', href: '/department'});
      }
      links.push({label: 'Reports', href: '/reports'});
      links.push({label: 'System Health', href: '/health'});
      links.push({label: 'Audit Trail', href: '/audit'});
      links.push({label: 'Account Settings', href: '/account'});

      navEl.innerHTML = links.map(l =>
        `<a href="${l.href}" class="nav-link">${l.label}</a>`
      ).join('');

      const current = window.location.pathname;
      $$('.nav-link', navEl).forEach(a => {
        if (a.getAttribute('href') === current) a.classList.add('active');
      });

      updateNotifBadge();
    });
  }

  function updateNotifBadge() {
    api('/api/notifications/unread').then(d => {
      const dashboardLink = document.querySelector('a[href="/dashboard"]');
      if (dashboardLink && d.count > 0) {
        let badge = dashboardLink.querySelector('.notif-badge');
        if (!badge) { badge = document.createElement('span'); badge.className = 'notif-badge'; dashboardLink.appendChild(badge); }
        badge.textContent = d.count;
      }
    }).catch(() => {});
  }

  // ─── Dashboard / Home ────────────────────────────────────

  function renderDashboard(contentEl) {
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    Promise.all([
      api('/api/stats'),
      api('/api/audit-log')
    ]).then(([stats, logs]) => {
      contentEl.innerHTML = `
        <div class="welcome-section">
          <p style="color:var(--text-secondary);margin-bottom:1.5rem">
            Welcome, <strong>${escapeHtml(document.getElementById('sidebar-username')?.textContent || 'User')}</strong>
          </p>
          <div class="card-grid">
            <div class="card stat-card"><div class="stat-value">${stats.circulars}</div><div class="stat-label">Circulars Ingested</div></div>
            <div class="card stat-card"><div class="stat-value">${stats.maps}</div><div class="stat-label">Total MAPs</div></div>
            <div class="card stat-card"><div class="stat-value">${stats.validated}</div><div class="stat-label">Validated</div></div>
            <div class="card stat-card"><div class="stat-value" style="color:${stats.breached > 0 ? 'var(--danger)' : 'var(--text)'}">${stats.breached}</div><div class="stat-label">Breached/Escalated</div></div>
            <div class="card stat-card"><div class="stat-value" style="font-size:1.2rem">${stats.llm_ok ? '✅ Online' : '❌ Offline'}</div><div class="stat-label">LLM Server</div></div>
            <div class="card stat-card"><div class="stat-value" style="font-size:1.2rem;color:${stats.chain_valid ? 'var(--success)' : 'var(--danger)'}">${stats.chain_valid ? '✅ Valid' : '❌ Tampered'}</div><div class="stat-label">Blockchain (${stats.blocks} blocks)</div></div>
          </div>

          <div class="welcome-actions">
            <div class="action-card">
              <h3>📥 Ingest Circular</h3>
              <p>Upload a PDF circular for processing</p>
              <div class="upload-zone" id="upload-zone"><p>Drop PDF here or click to upload</p><input type="file" accept=".pdf" id="file-input"></div>
            </div>
            <div class="action-card">
              <h3>📊 Reports</h3>
              <p>View and download compliance reports</p>
              <a href="/reports" class="btn btn-secondary btn-sm">View Reports</a>
            </div>
            <div class="action-card">
              <h3>🔗 Audit Trail</h3>
              <p>Blockchain with tamper detection demo</p>
              <a href="/audit" class="btn btn-secondary btn-sm">View Audit Trail</a>
            </div>
          </div>

          <h3 style="margin-top:2rem;margin-bottom:0.75rem;font-size:1rem">Recent Activity</h3>
          ${logs.length ? renderTable(['created_at','username','action','details'],
            logs.slice(0,10),
            {created_at:'Time', username:'User', action:'Action', details:'Details'}
          ) : '<p style="color:var(--text-muted)">No activity yet</p>'}
        </div>`;

      setupUpload();
    }).catch(() => { contentEl.innerHTML = '<div class="alert alert-error">Failed to load data</div>'; });
  }

  function setupUpload() {
    const zone = document.getElementById('upload-zone');
    const input = document.getElementById('file-input');
    if (!zone || !input) return;
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('dragover'); if (e.dataTransfer.files.length) input.files = e.dataTransfer.files; });
    input.addEventListener('change', async () => {
      if (!input.files.length) return;
      const f = input.files[0];
      if (!f.name.endsWith('.pdf')) { showAlert('PDF files only', 'error'); return; }
      const fd = new FormData(); fd.append('file', f);
      zone.innerHTML = '<p>Uploading...</p>';
      try {
        const r = await fetch('/api/circulars/ingest', {method:'POST', body:fd});
        const d = await r.json();
        if (d.ok) { zone.innerHTML = '<p style="color:var(--success)">✅ Uploaded! Refresh to see it.</p>'; setTimeout(() => renderDashboard($('#page-content')), 2000); }
        else { zone.innerHTML = `<p style="color:var(--danger)">Error: ${d.error}</p>`; }
      } catch(e) { zone.innerHTML = '<p style="color:var(--danger)">Upload failed</p>'; }
    });
  }

  function showAlert(msg, type) {
    const el = document.getElementById('page-content');
    if (!el) return;
    const a = document.createElement('div');
    a.className = `alert alert-${type}`;
    a.textContent = msg;
    el.prepend(a);
    setTimeout(() => a.remove(), 4000);
  }

  // ─── CCO Dashboard ──────────────────────────────────────

  function renderCCO(contentEl) {
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    Promise.all([
      api('/api/stats'),
      api('/api/circulars'),
      api('/api/maps')
    ]).then(([stats, circs, maps]) => {
      contentEl.innerHTML = `
        <div class="card-grid">
          <div class="card stat-card"><div class="stat-value">${stats.circulars}</div><div class="stat-label">Circulars</div></div>
          <div class="card stat-card"><div class="stat-value">${stats.maps}</div><div class="stat-label">MAPs</div></div>
          <div class="card stat-card"><div class="stat-value">${stats.validated}</div><div class="stat-label">Validated</div></div>
          <div class="card stat-card"><div class="stat-value" style="color:${stats.breached > 0 ? 'var(--danger)' : 'var(--text)'}">${stats.breached}</div><div class="stat-label">Overdue</div></div>
        </div>

        <div class="btn-group">
          <button class="btn btn-primary btn-sm" onclick="runAgent('route')">🔄 Route MAPs</button>
          <button class="btn btn-primary btn-sm" onclick="runAgent('validate')">✓ Validate</button>
          <button class="btn btn-primary btn-sm" onclick="runAgent('escalate')">🔺 Escalate</button>
          <button class="btn btn-secondary btn-sm" onclick="location.reload()">↻ Refresh</button>
        </div>

        <div class="tabs">
          <div class="tab active" data-tab="circulars">Circulars (${circs.length})</div>
          <div class="tab" data-tab="maps">MAPs (${maps.length})</div>
        </div>
        <div class="tab-content active" id="tab-circulars">
          ${circs.length ? renderTable(['id','circular_number','department_code','issue_date','subject_line','ingested_at'], circs, {id:'ID', circular_number:'Number', department_code:'Dept', issue_date:'Date', subject_line:'Subject', ingested_at:'Ingested'}) : '<p style="color:var(--text-muted);padding:1rem">No circulars</p>'}
        </div>
        <div class="tab-content" id="tab-maps">
          ${maps.length ? renderTable(['id','circular_number','map_text','assigned_to','deadline_date','status'], maps, {id:'ID', circular_number:'Circ', map_text:'Action', assigned_to:'Dept', deadline_date:'Deadline', status:'Status'}, true) : '<p style="color:var(--text-muted);padding:1rem">No MAPs</p>'}
        </div>`;

      setupTabs();
    }).catch(() => { contentEl.innerHTML = '<div class="alert alert-error">Failed to load</div>'; });
  }

  window.runAgent = function(action) {
    const btn = document.querySelector(`button[onclick*="${action}"]`);
    if (btn) { btn.disabled = true; btn.textContent = 'Running...'; }
    api(`/api/agents/${action}`, {method:'POST'}).then(d => {
      const msg = action === 'route' ? `Routed ${d.routed} MAPs` :
                  action === 'validate' ? `${d.validated} validated, ${d.breaches} breached` :
                  `Escalated ${d.escalated}`;
      showAlert(msg, 'success');
      setTimeout(() => location.reload(), 1000);
    }).catch(() => { showAlert('Agent action failed', 'error'); if(btn) btn.disabled = false; });
  };

  // ─── Department Dashboard ───────────────────────────────

  function renderDepartment(contentEl) {
    const deptRole = window.__DEPT_ROLE__ || '';
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    const deptEl = document.getElementById('dept-name');
    if (deptEl) deptEl.textContent = deptName(deptRole);

    api('/api/maps').then(maps => {
      const total = maps.length;
      const validated = maps.filter(m => m.status === 'VALIDATED').length;
      const breached = maps.filter(m => m.status === 'BREACHED' || m.status === 'ESCALATED').length;
      const pending = total - validated - breached;

      contentEl.innerHTML = `
        <div class="card-grid">
          <div class="card stat-card"><div class="stat-value">${total}</div><div class="stat-label">Assigned to You</div></div>
          <div class="card stat-card"><div class="stat-value">${pending}</div><div class="stat-label">Pending</div></div>
          <div class="card stat-card"><div class="stat-value" style="color:var(--success)">${validated}</div><div class="stat-label">Validated</div></div>
          <div class="card stat-card"><div class="stat-value" style="color:var(--danger)">${breached}</div><div class="stat-label">Breached</div></div>
        </div>

        <h3 style="margin:1.5rem 0 0.75rem">Your MAPs</h3>
        ${maps.length ? renderTable(['id','circular_number','map_text','deadline_date','status'], maps, {id:'ID', circular_number:'Circular', map_text:'Action Item', deadline_date:'Deadline', status:'Status'}, true) : '<p style="color:var(--text-muted)">No MAPs assigned yet</p>'}

        <h3 style="margin:1.5rem 0 0.75rem">Submit Evidence</h3>
        <div class="card" style="max-width:600px">
          <div class="form-group">
            <label>Select MAP</label>
            <select class="form-control" id="evidence-map">
              ${maps.filter(m => m.status !== 'VALIDATED').map(m => `<option value="${m.id}">#${m.id}: ${escapeHtml(m.map_text || '').substring(0,80)}</option>`).join('')}
            </select>
          </div>
          <div class="form-group">
            <label>Evidence Description</label>
            <textarea class="form-control" id="evidence-text" rows="3" placeholder="Describe the evidence..."></textarea>
          </div>
          <button class="btn btn-primary" onclick="submitEvidence()">Submit Evidence</button>
        </div>`;
    }).catch(() => { contentEl.innerHTML = '<div class="alert alert-error">Failed to load</div>'; });
  }

  window.submitEvidence = function() {
    const mapId = document.getElementById('evidence-map')?.value;
    const text = document.getElementById('evidence-text')?.value;
    if (!mapId || !text) { showAlert('Select a MAP and enter evidence', 'error'); return; }
    const btn = document.querySelector('button[onclick="submitEvidence()"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Submitting...'; }
    api('/api/maps/evidence', {method:'POST', body:JSON.stringify({map_id: parseInt(mapId), evidence_text: text})}).then(d => {
      if (d.ok) { showAlert('Evidence submitted!', 'success'); setTimeout(() => location.reload(), 1000); }
      else { showAlert(d.error || 'Failed', 'error'); if(btn) btn.disabled = false; }
    }).catch(() => { showAlert('Network error', 'error'); if(btn) btn.disabled = false; });
  };

  // ─── Audit Trail ─────────────────────────────────────────

  function renderAudit(contentEl) {
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    api('/api/chain/verify').then(status => {
      contentEl.innerHTML = `
        <div class="alert ${status.valid ? 'alert-success' : 'alert-error'}">
          <strong>Blockchain: ${status.valid ? '✅ INTACT' : '❌ TAMPERED'}</strong>
          ${status.valid ? '' : `<br>${status.errors.join('<br>')}`}
          ${status.count} blocks in chain
        </div>
        <div id="chain-blocks"></div>
        <h3 style="margin:1.5rem 0 0.75rem">Tamper Test Demo</h3>
        <div class="card" style="max-width:500px">
          <div class="form-row">
            <div class="form-group"><label>Block Index</label><input type="number" class="form-control" id="tamper-index" value="1" min="1"></div>
            <div class="form-group"><label>Field</label><select class="form-control" id="tamper-field"><option>action</option><option>data_hash</option><option>timestamp</option><option>prev_hash</option></select></div>
          </div>
          <button class="btn btn-danger" onclick="runTamperTest()">💥 Corrupt & Detect</button>
          <div id="tamper-result" style="margin-top:1rem"></div>
        </div>`;

      renderChainBlocks();
    });
  }

  function renderChainBlocks() {
    const el = document.getElementById('chain-blocks');
    if (!el) return;
    api('/api/chain').then(chain => {
      blocksCache = chain;
      el.innerHTML = chain.map(b => `
        <div class="block">
          <div class="block-header">
            <span class="block-index">Block #${b.index}</span>
            <span class="block-action">${escapeHtml(b.action)}</span>
          </div>
          <div class="block-detail">
            <span>time:</span> ${escapeHtml(b.timestamp)}<br>
            <span>data_hash:</span> ${shortHash(b.data_hash)}<br>
            <span>prev_hash:</span> ${shortHash(b.prev_hash)}<br>
            <span>block_hash:</span> ${shortHash(b.block_hash)}
          </div>
        </div>
      `).join('');
    }).catch(() => {});
  }

  window.runTamperTest = function() {
    const idx = parseInt(document.getElementById('tamper-index')?.value || '1');
    const field = document.getElementById('tamper-field')?.value || 'action';
    const resultEl = document.getElementById('tamper-result');
    if (!resultEl) return;
    resultEl.innerHTML = '<p style="color:var(--text-muted)">Testing...</p>';

    api('/api/chain/corrupt', {
      method:'POST',
      body: JSON.stringify({index: idx, field, value: 'TAMPERED_BY_DEMO'})
    }).then(d => {
      if (d.tamper_detected) {
        resultEl.innerHTML = `<div class="alert alert-error"><strong>✅ Tampering Detected!</strong><br>${d.errors.map(e => escapeHtml(e)).join('<br>')}<br><em>Blockchain auto-restored</em></div>`;
      } else {
        resultEl.innerHTML = '<div class="alert alert-warning">Tamper not detected (unexpected)</div>';
      }
      renderChainBlocks();
    }).catch(() => { resultEl.innerHTML = '<div class="alert alert-error">Test failed</div>'; });
  };

  // ─── User Management ────────────────────────────────────

  function renderUsers(contentEl) {
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    api('/api/users').then(users => {
      contentEl.innerHTML = `
        <div class="tabs">
          <div class="tab active" data-tab="list">Users (${users.length})</div>
          <div class="tab" data-tab="create">Create User</div>
        </div>
        <div class="tab-content active" id="tab-list">
          ${renderTable(['id','username','display_name','role','department_code','is_active','last_login'], users, {id:'ID', username:'Username', display_name:'Name', role:'Role', department_code:'Dept', is_active:'Active', last_login:'Last Login'})}
        </div>
        <div class="tab-content" id="tab-create">
          <div class="card" style="max-width:500px">
            <div class="form-group"><label>Username</label><input class="form-control" id="cu-username" required></div>
            <div class="form-row">
              <div class="form-group"><label>Password</label><input type="password" class="form-control" id="cu-password" required></div>
              <div class="form-group"><label>Confirm Password</label><input type="password" class="form-control" id="cu-password2"></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label>Display Name</label><input class="form-control" id="cu-display"></div>
              <div class="form-group"><label>Role</label><select class="form-control" id="cu-role">${['CCO','KYC','Payments','IT_Security','Treasury','Credit_Risk','Forex'].map(r => `<option value="${r}">${r}</option>`).join('')}</select></div>
            </div>
            <div class="form-group"><label>Department Code</label><input class="form-control" id="cu-dept" placeholder="e.g. DOR.AML"></div>
            <button class="btn btn-primary" onclick="createUser()">Create User</button>
          </div>
        </div>`;
      setupTabs();
    });
  }

  window.createUser = function() {
    const uname = document.getElementById('cu-username')?.value;
    const pw = document.getElementById('cu-password')?.value;
    const pw2 = document.getElementById('cu-password2')?.value;
    if (!uname || uname.length < 3) { showAlert('Username must be 3+ chars', 'error'); return; }
    if (!pw || pw.length < 6) { showAlert('Password must be 6+ chars', 'error'); return; }
    if (pw !== pw2) { showAlert('Passwords do not match', 'error'); return; }
    const btn = document.querySelector('button[onclick="createUser()"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Creating...'; }
    api('/api/users/create', {method:'POST', body: JSON.stringify({
      username: uname,
      password: pw,
      role: document.getElementById('cu-role')?.value || 'KYC',
      display_name: document.getElementById('cu-display')?.value || uname,
      department_code: document.getElementById('cu-dept')?.value || ''
    })}).then(d => {
      if (d.ok) { showAlert('User created!', 'success'); setTimeout(() => location.reload(), 1000); }
      else { showAlert(d.error || 'Failed', 'error'); if(btn) btn.disabled = false; }
    }).catch(() => { showAlert('Network error', 'error'); if(btn) btn.disabled = false; });
  };

  // ─── Health Dashboard ────────────────────────────────────

  function renderHealth(contentEl) {
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    api('/api/health').then(h => {
      contentEl.innerHTML = `
        <div class="card-grid">
          <div class="card stat-card"><div class="stat-value" style="font-size:1.2rem;color:${h.llm ? 'var(--success)' : 'var(--danger)'}">${h.llm ? '✅ Online' : '❌ Offline'}</div><div class="stat-label">LLM Server</div></div>
          <div class="card stat-card"><div class="stat-value" style="font-size:1.2rem;color:${h.chain_valid ? 'var(--success)' : 'var(--danger)'}">${h.chain_valid ? '✅ Valid' : '❌ Tampered'}</div><div class="stat-label">Blockchain</div></div>
          <div class="card stat-card"><div class="stat-value">${h.db_size > 0 ? (h.db_size / 1024).toFixed(0) + ' KB' : '—'}</div><div class="stat-label">Database Size</div></div>
          <div class="card stat-card"><div class="stat-value">${h.backups}</div><div class="stat-label">Backups</div></div>
        </div>

        <div class="card-grid" style="grid-template-columns:repeat(4,1fr)">
          <div class="card stat-card"><div class="stat-value" style="font-size:1.1rem">${h.queue.pending}</div><div class="stat-label">Queue Pending</div></div>
          <div class="card stat-card"><div class="stat-value" style="font-size:1.1rem">${h.queue.processing}</div><div class="stat-label">Processing</div></div>
          <div class="card stat-card"><div class="stat-value" style="font-size:1.1rem;color:${h.queue.failed > 0 ? 'var(--danger)' : 'var(--text)'}">${h.queue.failed}</div><div class="stat-label">Failed</div></div>
          <div class="card stat-card"><div class="stat-value" style="font-size:1.1rem">${h.queue.done}</div><div class="stat-label">Completed</div></div>
        </div>

        <div class="btn-group" style="margin-top:1rem">
          <button class="btn btn-primary btn-sm" onclick="createBackup()">💾 Create Backup Now</button>
          <button class="btn btn-secondary btn-sm" onclick="location.reload()">↻ Refresh</button>
        </div>
        <div id="backup-result"></div>`;
    });
  }

  window.createBackup = function() {
    const btn = document.querySelector('button[onclick="createBackup()"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Creating...'; }
    const el = document.getElementById('backup-result');
    api('/api/backup/create', {method:'POST'}).then(d => {
      if (d.ok) { el.innerHTML = `<div class="alert alert-success">Backup created: ${d.name}</div>`; }
      else { el.innerHTML = '<div class="alert alert-error">Backup failed</div>'; }
      if (btn) btn.disabled = false;
    }).catch(() => { el.innerHTML = '<div class="alert alert-error">Backup failed</div>'; if(btn) btn.disabled = false; });
  };

  // ─── Reports ─────────────────────────────────────────────

  function renderReports(contentEl) {
    contentEl.innerHTML = '<div class="loading">Loading...</div>';
    api('/api/reports/data').then(rows => {
      if (!rows.length) { contentEl.innerHTML = '<p style="color:var(--text-muted)">No data yet</p>'; return; }
      const total = rows.reduce((s, r) => s + r.total, 0);
      const validated = rows.reduce((s, r) => s + r.validated, 0);
      const breached = rows.reduce((s, r) => s + r.breached, 0);

      contentEl.innerHTML = `
        <div class="card-grid">
          <div class="card stat-card"><div class="stat-value">${rows.length}</div><div class="stat-label">Departments</div></div>
          <div class="card stat-card"><div class="stat-value">${total}</div><div class="stat-label">Total MAPs</div></div>
          <div class="card stat-card"><div class="stat-value">${validated}</div><div class="stat-label">Validated</div></div>
          <div class="card stat-card"><div class="stat-value" style="color:${breached > 0 ? 'var(--danger)' : 'var(--text)'}">${breached}</div><div class="stat-label">Breached</div></div>
        </div>
        ${renderTable(['department','total','validated','pending','breached','escalated','compliance_rate'], rows, {department:'Department', total:'Total', validated:'Validated', pending:'Pending', breached:'Breached', escalated:'Escalated', compliance_rate:'Rate'})}
        <div class="btn-group" style="margin-top:1rem">
          <button class="btn btn-primary btn-sm" onclick="exportCSV()">📥 Download CSV</button>
        </div>`;
    });
  }

  window.exportCSV = function() {
    api('/api/reports/data').then(rows => {
      if (!rows.length) return;
      const headers = Object.keys(rows[0]);
      const csv = [headers.join(','), ...rows.map(r => headers.map(h => `"${r[h]}"`).join(','))].join('\n');
      const blob = new Blob([csv], {type: 'text/csv'});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `compliance_report_${new Date().toISOString().slice(0,10)}.csv`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  };

  // ─── Utility: Table Renderer ─────────────────────────────

  function renderTable(fields, data, labels, showStatus) {
    if (!data || !data.length) return '<p style="color:var(--text-muted);padding:0.5rem">No data</p>';
    return `<div class="table-container"><table>
      <thead><tr>${fields.map(f => `<th>${labels[f] || f}</th>`).join('')}</tr></thead>
      <tbody>${data.map(row => `<tr>${fields.map(f => {
        let val = row[f];
        if (val === null || val === undefined) val = '—';
        if (f === 'status' && showStatus) val = `<span class="status-badge ${statusClass(val)}">${escapeHtml(val)}</span>`;
        if (f === 'is_active') val = val == 1 || val === true ? '✅' : '❌';
        if (f === 'deadline_date' && row.status === 'BREACHED') val = `<span style="color:var(--danger)">${escapeHtml(val)}</span>`;
        if (typeof val === 'string' && val.length > 100) val = escapeHtml(val.substring(0, 100)) + '...';
        else val = escapeHtml(String(val));
        return `<td>${val}</td>`;
      }).join('')}</tr>`).join('')}</tbody>
    </table></div>`;
  }

  // ─── Tabs ─────────────────────────────────────────────────

  function setupTabs() {
    $$('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        $$('.tab').forEach(t => t.classList.remove('active'));
        $$('.tab-content').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        const target = document.getElementById('tab-' + tab.dataset.tab);
        if (target) target.classList.add('active');
      });
    });
  }

  // ─── Router ──────────────────────────────────────────────

  function router() {
    const contentEl = document.getElementById('page-content');
    if (!contentEl) return;

    switch (PAGE) {
      case 'cco': renderCCO(contentEl); break;
      case 'department': renderDepartment(contentEl); break;
      case 'audit': renderAudit(contentEl); break;
      case 'users': renderUsers(contentEl); break;
      case 'health': renderHealth(contentEl); break;
      case 'reports': renderReports(contentEl); break;
      default: renderDashboard(contentEl); break;
    }
  }

  // ─── Init ────────────────────────────────────────────────

  document.addEventListener('DOMContentLoaded', () => {
    const isLogin = document.querySelector('.login-page');
    if (isLogin) return;

    buildSidebar();
    router();

    // Auto-refresh health page every 15s
    if (PAGE === 'health') {
      setInterval(() => {
        const contentEl = document.getElementById('page-content');
        if (contentEl && window.location.pathname === '/health') {
          api('/api/health').then(h => {
            const statEls = contentEl.querySelectorAll('.stat-value');
            if (statEls.length >= 4) {
              statEls[0].textContent = h.llm ? '✅ Online' : '❌ Offline';
              statEls[0].style.color = h.llm ? 'var(--success)' : 'var(--danger)';
            }
          });
        }
      }, 15000);
    }

    // Auto-refresh unread count
    setInterval(updateNotifBadge, 20000);
  });

})();
