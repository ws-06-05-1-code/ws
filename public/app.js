'use strict';

// ── State ────────────────────────────────────────────────────────────────────
let currentStep      = 1;
let sessionId        = null;
let issuedCert       = null;
let pollTimer        = null;

// ── Bootstrap ────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const res  = await fetch('/api/config');
    const data = await res.json();
    const suffix = data.dnsSuffix;
    if (suffix) {
      // Pre-fill CEP and CES URLs with the primary DNS suffix
      const cepDefault = `https://${suffix}/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP`;
      const cesDefault = `https://${suffix}/CertSrv/CES/service.svc/CES`;
      if (!el('cepUrl').value) el('cepUrl').value = cepDefault;
      if (!el('cesUrl').value) el('cesUrl').value = cesDefault;
    }
  } catch {
    // Non-fatal — user can type URLs manually
  }
});

// ── Step Navigation ──────────────────────────────────────────────────────────
function showStep(n) {
  // Stop polling if leaving step 3
  if (n !== 3 && pollTimer) { clearInterval(pollTimer); pollTimer = null; }

  document.querySelectorAll('.step-panel').forEach(p => p.classList.remove('active'));
  document.getElementById(`panel-${n}`).classList.add('active');

  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById(`nav-${i}`);
    el.classList.remove('active', 'done');
    if (i < n)      el.classList.add('done');
    else if (i === n) el.classList.add('active');
  }
  currentStep = n;
}

// ── Step 1 → Step 2 (with validation) ────────────────────────────────────────
function goToStep2() {
  const username = val('username');
  const password = val('password');
  const cesUrl   = val('cesUrl');
  const template = resolvedTemplateName();

  if (!username) return alert('Username is required.');
  if (!password) return alert('Password is required.');
  if (!cesUrl)   return alert('CES Endpoint URL is required.');
  if (!cesUrl.startsWith('http')) return alert('CES Endpoint URL must start with http:// or https://.');
  if (!template) return alert('A Certificate Template name is required. Load from CEP or enter manually.');

  showStep(2);
}

// Returns the resolved template internal name from select or manual input
function resolvedTemplateName() {
  const sel = el('templateSelect').value;
  if (sel && sel !== '__manual__' && sel !== '') return sel;
  return val('templateName');
}

// Show/hide manual input based on select
function onTemplateChange() {
  const sel     = el('templateSelect').value;
  const manualField = el('template-manual-field');
  // Show manual input when nothing loaded from CEP or user picks "enter manually"
  if (!sel || sel === '__manual__') {
    manualField.classList.remove('hidden');
  } else {
    manualField.classList.add('hidden');
    el('templateName').value = sel; // keep in sync for display
  }
}

// ── Load Templates from CEP ───────────────────────────────────────────────────
async function loadTemplates() {
  const cepUrl  = val('cepUrl');
  const username = val('username');
  const password = val('password');

  if (!cepUrl)   return alert('Enter the CEP Endpoint URL first.');
  if (!username) return alert('Enter your username first.');
  if (!password) return alert('Enter your password first.');

  const statusEl = el('template-status');
  const btn      = el('btn-load-templates');
  btn.disabled   = true;
  btn.textContent = 'Loading…';
  statusEl.className = 'notice notice-info';
  statusEl.textContent = 'Querying Certificate Enrollment Policy service…';
  statusEl.classList.remove('hidden');

  try {
    const res  = await fetch('/api/templates', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({
        cepUrl,
        username,
        password,
        allowSelfSigned: document.getElementById('allowSelfSigned').checked,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Server error ${res.status}`);

    const { templates, cesUris } = data;

    // Populate template select
    const sel = el('templateSelect');
    sel.innerHTML = '';

    if (templates.length === 0) {
      sel.innerHTML = '<option value="">No enrollable templates found</option>';
    } else {
      sel.innerHTML = '<option value="">— select a template —</option>';
      for (const t of templates) {
        const opt = document.createElement('option');
        opt.value       = t.commonName;
        opt.textContent = t.friendlyName === t.commonName
          ? t.commonName
          : `${t.friendlyName} (${t.commonName})`;
        sel.appendChild(opt);
      }
      // Add manual entry escape hatch
      const manual = document.createElement('option');
      manual.value       = '__manual__';
      manual.textContent = 'Enter name manually…';
      sel.appendChild(manual);
    }

    // Auto-fill CES URL: prefer clientAuthentication=3 (Username/Password)
    const upUri = cesUris.find(u => u.authType === '3') || cesUris[0];
    if (upUri && !val('cesUrl').includes('CES')) {
      el('cesUrl').value = upUri.uri;
    } else if (upUri && !el('cesUrl').value) {
      el('cesUrl').value = upUri.uri;
    }

    onTemplateChange();

    statusEl.className   = 'notice notice-success';
    statusEl.textContent = `Loaded ${templates.length} template${templates.length !== 1 ? 's' : ''}.`;
  } catch (err) {
    statusEl.className   = 'notice notice-error';
    statusEl.textContent = `Failed to load templates: ${err.message}`;
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Load Templates';
  }
}

// ── Step 2: Submit Request ────────────────────────────────────────────────────
async function submitRequest() {
  const cn = val('cn');
  if (!cn) return alert('Common Name (CN) is required.');

  // Reset step 3 UI
  show('s3-spinner');
  hide('s3-result');
  hide('notice-pending');
  hide('notice-issued');
  hide('notice-denied');
  hide('notice-error');
  el('s3-actions').style.display = 'none';
  el('btn-to-install').classList.add('hidden');
  el('s3-spinner-msg').textContent = 'Generating key pair and submitting request…';
  issuedCert = null;

  showStep(3);

  const sansRaw = val('sans');
  const sans    = sansRaw ? sansRaw.split('\n').map(s => s.trim()).filter(Boolean) : [];

  const payload = {
    cesUrl:       val('cesUrl'),
    username:     val('username'),
    password:     val('password'),
    templateName: resolvedTemplateName(),
    allowSelfSigned: document.getElementById('allowSelfSigned').checked,
    keySize:      parseInt(val('keySize'), 10) || 2048,
    subject: {
      cn,
      org:      val('org'),
      ou:       val('ou'),
      locality: val('locality'),
      state:    val('state'),
      country:  val('country'),
      sans,
    },
  };

  try {
    const res  = await fetch('/api/enroll', { method: 'POST', headers: jsonHeaders(), body: JSON.stringify(payload) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Server error ${res.status}`);

    sessionId = data.sessionId;
    hide('s3-spinner');
    show('s3-result');
    el('s3-actions').style.display = 'flex';
    applyStatus(data);
  } catch (err) {
    hide('s3-spinner');
    show('s3-result');
    el('s3-actions').style.display = 'flex';
    showEnrollError(err.message);
  }
}

// ── Apply status response to Step 3 UI ───────────────────────────────────────
function applyStatus(data) {
  el('s3-req-id').textContent      = data.requestId  || '—';
  el('s3-disposition').textContent = data.disposition || data.status || '—';

  const badge = el('s3-badge');

  switch (data.status) {
    case 'issued':
      badge.textContent  = 'Issued';
      badge.className    = 'badge badge-issued';
      issuedCert         = data.certificate;
      show('notice-issued');
      el('btn-to-install').classList.remove('hidden');
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      break;

    case 'pending':
      badge.textContent = 'Pending Approval';
      badge.className   = 'badge badge-pending';
      show('notice-pending');
      el('last-checked').textContent = new Date().toLocaleTimeString();
      startPolling();
      break;

    case 'denied':
      badge.textContent = 'Denied';
      badge.className   = 'badge badge-denied';
      show('notice-denied');
      if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      break;

    default:
      badge.textContent = data.status || 'Unknown';
      badge.className   = 'badge badge-unknown';
  }
}

function showEnrollError(msg) {
  el('s3-badge').textContent = 'Error';
  el('s3-badge').className   = 'badge badge-denied';
  el('notice-error-msg').textContent = msg;
  show('notice-error');
  show('s3-result');
}

// ── Polling ───────────────────────────────────────────────────────────────────
function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(pollStatus, 30_000);
}

async function pollStatus() {
  if (!sessionId) return;
  try {
    const res  = await fetch(`/api/status/${sessionId}`);
    const data = await res.json();
    if (!res.ok) { console.warn('[poll]', data.error); return; }

    el('last-checked').textContent = new Date().toLocaleTimeString();

    if (data.status === 'issued' || data.status === 'denied') {
      hide('notice-pending');
      applyStatus(data);
    }
  } catch (err) {
    console.warn('[poll error]', err.message);
  }
}

// ── Cancel / Back from Step 3 ─────────────────────────────────────────────────
function cancelRequest() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  showStep(2);
}

// ── Step 4: Install ───────────────────────────────────────────────────────────
async function doInstall() {
  if (!issuedCert) {
    alert('No certificate available. Please return to step 3 and wait for issuance.');
    return;
  }

  hide('install-success');
  hide('install-error');
  el('btn-install').disabled = true;
  el('btn-install').textContent = 'Installing…';

  const payload = {
    sessionId,
    certificate:   issuedCert,
    storeLocation: val('storeLocation'),
    storeName:     val('storeName'),
  };

  try {
    const res  = await fetch('/api/install', { method: 'POST', headers: jsonHeaders(), body: JSON.stringify(payload) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Server error ${res.status}`);

    el('thumbprint').textContent = data.thumbprint || '(none returned)';
    show('install-success');
    el('btn-new').classList.remove('hidden');
  } catch (err) {
    el('install-error-msg').textContent = err.message;
    show('install-error');
  } finally {
    el('btn-install').disabled = false;
    el('btn-install').textContent = '🔒 Install to Certificate Store';
  }
}

// ── Reset ─────────────────────────────────────────────────────────────────────
function resetWizard() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  sessionId  = null;
  issuedCert = null;

  // Clear password only; preserve URL and template fields for convenience
  document.getElementById('password').value = '';
  hide('template-status');

  // Reset step 3
  show('s3-spinner');
  hide('s3-result');
  el('s3-actions').style.display   = 'none';
  el('btn-to-install').classList.add('hidden');
  ['notice-pending','notice-issued','notice-denied','notice-error'].forEach(hide);

  // Reset step 4
  hide('install-success');
  hide('install-error');
  el('btn-new').classList.add('hidden');

  showStep(1);
}

// ── Tiny helpers ──────────────────────────────────────────────────────────────
const el   = id => document.getElementById(id);
const val  = id => (el(id)?.value || '').trim();
const show = id => el(id)?.classList.remove('hidden');
const hide = id => el(id)?.classList.add('hidden');
const jsonHeaders = () => ({ 'Content-Type': 'application/json' });
