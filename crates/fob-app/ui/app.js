'use strict';

const invoke = (cmd, args) => window.__TAURI__.core.invoke(cmd, args);

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));
const initials = (s) => (s || '?').trim().slice(0, 1).toUpperCase();

// ── App state ──────────────────────────────────────────────────────────
const state = {
  devices: [],
  selectedDevice: null,   // { name, size_display, path, has_fob_vault }
  blob: null,             // VaultBlob from backend
  header: null,           // VaultHeaderDto, cached at unlock time
  tab: 'passwords',
  selectedId: null,
  revealed: false,
  search: '',
  totpTimer: null,
  pendingRecoveryBlob: null, // set between recover_vault and set_new_passphrase
  confirmAction: null,    // fn to run when modal-confirm is accepted
};

function showScreen(id) {
  document.querySelectorAll('.screen').forEach((el) => el.classList.remove('active'));
  $(id).classList.add('active');
}

let toastTimer = null;
function toast(msg, isErr) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.toggle('err', !!isErr);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}

function friendlyError(e) {
  return typeof e === 'string' ? e : (e && e.message) ? e.message : 'Something went wrong.';
}

// ── Boot / device picker ──────────────────────────────────────────────
async function boot() {
  showScreen('screen-boot');
  await refreshDevices();
  if (state.devices.length === 1) {
    selectDevice(state.devices[0]);
  } else {
    renderDevicePicker();
    showScreen('screen-picker');
  }
}

async function refreshDevices() {
  state.devices = await invoke('list_devices');
}

function renderDevicePicker() {
  const list = $('device-list');
  if (state.devices.length === 0) {
    list.innerHTML = `<div class="empty-devices">No USB drives detected.<br>Plug one in, then rescan.</div>`;
    $('picker-sub').textContent = 'No drives found';
    return;
  }
  $('picker-sub').textContent = 'Choose the USB drive to use as your vault';
  list.innerHTML = state.devices.map((d, i) => `
    <div class="device-item" data-idx="${i}">
      <span class="di-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 3l7 7-8.5 8.5a2.1 2.1 0 0 1-3-3L18 7"/><rect x="2" y="14" width="8" height="8" rx="1"/></svg></span>
      <div>
        <div class="di-name">${esc(d.name)}</div>
        <div class="di-meta">${esc(d.size_display)}</div>
      </div>
      <span class="di-tag ${d.has_fob_vault ? 'has-vault' : ''}">${d.has_fob_vault ? 'vault present' : 'new drive'}</span>
    </div>
  `).join('');
  list.querySelectorAll('.device-item').forEach((el) => {
    el.addEventListener('click', () => selectDevice(state.devices[Number(el.dataset.idx)]));
  });
}

function selectDevice(dev) {
  state.selectedDevice = dev;
  if (dev.has_fob_vault) {
    $('unlock-sub').textContent = `${dev.name} · ${dev.size_display}`;
    $('unlock-error').classList.add('hidden');
    $('unlock-pass').value = '';
    showScreen('screen-unlock');
    $('unlock-pass').focus();
  } else {
    $('create-sub').textContent = `${dev.name} · ${dev.size_display}`;
    $('create-error').classList.add('hidden');
    $('create-pass').value = '';
    $('create-pass-confirm').value = '';
    $('create-recovery').checked = false;
    showScreen('screen-create');
    $('create-pass').focus();
  }
}

$('btn-rescan').addEventListener('click', async () => {
  await refreshDevices();
  renderDevicePicker();
});

// ── Create vault ────────────────────────────────────────────────────────
$('btn-create-back').addEventListener('click', () => showScreen('screen-picker'));

async function submitCreate() {
  const pass = $('create-pass').value;
  const confirm = $('create-pass-confirm').value;
  const err = $('create-error');
  err.classList.add('hidden');

  if (!pass) { err.textContent = 'Enter a passphrase.'; err.classList.remove('hidden'); return; }
  if (pass !== confirm) { err.textContent = "Passphrases don't match."; err.classList.remove('hidden'); return; }

  const btn = $('btn-create-submit');
  btn.disabled = true;
  try {
    const result = await invoke('create_vault', {
      device_path: state.selectedDevice.path,
      passphrase: pass,
      recovery_enabled: $('create-recovery').checked,
    });
    state.header = await invoke('vault_header_info', { device_path: state.selectedDevice.path });
    if (result.recovery_key_display) {
      $('recovery-key-text').textContent = result.recovery_key_display;
      state.pendingRecoveryBlob = result.blob;
      showScreen('screen-recovery-display');
    } else {
      enterDashboard(result.blob);
    }
  } catch (e) {
    err.textContent = friendlyError(e);
    err.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
}
$('btn-create-submit').addEventListener('click', submitCreate);
$('create-pass-confirm').addEventListener('keydown', (e) => { if (e.key === 'Enter') submitCreate(); });

$('btn-recovery-saved').addEventListener('click', () => {
  const blob = state.pendingRecoveryBlob;
  state.pendingRecoveryBlob = null;
  enterDashboard(blob);
});

// ── Unlock ──────────────────────────────────────────────────────────────
$('btn-unlock-back').addEventListener('click', () => showScreen('screen-picker'));
$('btn-use-recovery').addEventListener('click', () => {
  $('recover-error').classList.add('hidden');
  $('recover-key-input').value = '';
  showScreen('screen-recover');
});

async function submitUnlock() {
  const pass = $('unlock-pass').value;
  const err = $('unlock-error');
  err.classList.add('hidden');
  if (!pass) return;

  const btn = $('btn-unlock-submit');
  btn.disabled = true;
  try {
    const blob = await invoke('unlock_vault', { device_path: state.selectedDevice.path, passphrase: pass });
    state.header = await invoke('vault_header_info', { device_path: state.selectedDevice.path });
    enterDashboard(blob);
  } catch (e) {
    err.textContent = friendlyError(e);
    err.classList.remove('hidden');
    $('unlock-pass').value = '';
    $('unlock-pass').focus();
  } finally {
    btn.disabled = false;
  }
}
$('btn-unlock-submit').addEventListener('click', submitUnlock);
$('unlock-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') submitUnlock(); });

// ── Recover via key ───────────────────────────────────────────────────
$('btn-recover-back').addEventListener('click', () => showScreen('screen-unlock'));

$('btn-recover-submit').addEventListener('click', async () => {
  const key = $('recover-key-input').value.trim();
  const err = $('recover-error');
  err.classList.add('hidden');
  if (!key) return;

  const btn = $('btn-recover-submit');
  btn.disabled = true;
  try {
    const blob = await invoke('recover_vault', { device_path: state.selectedDevice.path, recovery_key: key });
    state.header = await invoke('vault_header_info', { device_path: state.selectedDevice.path });
    state.pendingRecoveryBlob = blob;
    $('set-pass-sub').textContent = `${blob.passwords.length + blob.totp.length + blob.ssh_keys.length + blob.notes.length} entries found — set a new passphrase to finish.`;
    $('set-pass-new').value = '';
    $('set-pass-error').classList.add('hidden');
    showScreen('screen-set-pass');
  } catch (e) {
    err.textContent = friendlyError(e);
    err.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

$('btn-set-pass-submit').addEventListener('click', async () => {
  const pass = $('set-pass-new').value;
  const err = $('set-pass-error');
  err.classList.add('hidden');
  if (!pass) { err.textContent = 'Enter a passphrase.'; err.classList.remove('hidden'); return; }

  const btn = $('btn-set-pass-submit');
  btn.disabled = true;
  try {
    await invoke('set_new_passphrase', { new_passphrase: pass });
    const blob = state.pendingRecoveryBlob;
    state.pendingRecoveryBlob = null;
    enterDashboard(blob);
  } catch (e) {
    err.textContent = friendlyError(e);
    err.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

// ── Dashboard entry / lock ──────────────────────────────────────────────
function enterDashboard(blob) {
  state.blob = blob;
  state.tab = 'passwords';
  state.selectedId = null;
  state.revealed = false;
  state.search = '';
  $('search-input').value = '';

  const dev = state.selectedDevice;
  $('sb-device-name').textContent = `${dev.name} · UNLOCKED`;
  $('dc-name').textContent = dev.name;
  $('dc-meta').textContent = `${dev.size_display} · ${state.header ? state.header.kdf_algorithm : ''} · v${state.header ? state.header.format_version : '?'}`;

  const chip = $('recovery-chip');
  const on = state.header && state.header.recovery_enabled;
  chip.textContent = on ? 'Recovery enabled' : 'No recovery key';
  chip.classList.toggle('good', !!on);
  chip.classList.toggle('warn', !on);

  invoke('ssh_agent_status').then((s) => {
    $('settings-ssh-status').textContent = s || 'not running';
  }).catch(() => {});

  setTab('passwords');
  showScreen('screen-dashboard');
}

$('btn-lock').addEventListener('click', async () => {
  stopTotpPolling();
  await invoke('lock_vault');
  state.blob = null;
  state.header = null;
  await boot();
});

document.querySelectorAll('.nav-item[data-tab]').forEach((el) => {
  el.addEventListener('click', () => setTab(el.dataset.tab));
});

const TAB_LABEL = { passwords: 'Passwords', totp: 'Two-Factor', ssh: 'SSH Keys', notes: 'Notes', security: 'Security', settings: 'Settings' };
const ENTRY_TABS = ['passwords', 'totp', 'ssh', 'notes'];

function setTab(tab) {
  stopTotpPolling();
  state.tab = tab;
  state.selectedId = null;
  state.revealed = false;

  document.querySelectorAll('.nav-item[data-tab]').forEach((el) => {
    el.setAttribute('aria-current', String(el.dataset.tab === tab));
  });
  $('topbar-title').textContent = TAB_LABEL[tab];

  const isEntryTab = ENTRY_TABS.includes(tab);
  $('search-wrap').classList.toggle('hidden', !isEntryTab);
  $('btn-add-entry').classList.toggle('hidden', !isEntryTab);
  $('entry-view').classList.toggle('hidden', !isEntryTab);
  $('security-view').classList.toggle('hidden', tab !== 'security');
  $('settings-view').classList.toggle('hidden', tab !== 'settings');

  if (isEntryTab) {
    renderEntryList();
    renderDetail();
  } else if (tab === 'security') {
    renderSecurity();
  }
}

// ── Entry list / detail ──────────────────────────────────────────────
function entriesForTab() {
  const map = { passwords: 'passwords', totp: 'totp', ssh: 'ssh_keys', notes: 'notes' };
  return state.blob[map[state.tab]] || [];
}

function entryLabel(kind, e) {
  if (kind === 'passwords') return { title: e.name, sub: e.username };
  if (kind === 'totp') return { title: e.issuer, sub: e.account };
  if (kind === 'ssh') return { title: e.name, sub: e.fingerprint };
  return { title: e.title, sub: '' };
}

$('search-input').addEventListener('input', (e) => {
  state.search = e.target.value.toLowerCase();
  renderEntryList();
});

function renderEntryList() {
  $('count-passwords').textContent = state.blob.passwords.length;
  $('count-totp').textContent = state.blob.totp.length;
  $('count-ssh').textContent = state.blob.ssh_keys.length;
  $('count-notes').textContent = state.blob.notes.length;

  const list = $('entry-list');
  let entries = entriesForTab();
  if (state.search) {
    entries = entries.filter((e) => {
      const { title, sub } = entryLabel(state.tab, e);
      return `${title} ${sub}`.toLowerCase().includes(state.search);
    });
  }

  if (entries.length === 0) {
    list.innerHTML = `<div class="empty-list">${state.search ? 'No matches.' : 'Nothing here yet — press Add.'}</div>`;
    return;
  }

  if (!state.selectedId || !entries.some((e) => e.id === state.selectedId)) {
    state.selectedId = entries[0].id;
  }

  list.innerHTML = entries.map((e) => {
    const { title, sub } = entryLabel(state.tab, e);
    const current = e.id === state.selectedId;
    return `
      <div class="entry-row" data-id="${e.id}" aria-current="${current}">
        <div class="avatar">${esc(initials(title))}</div>
        <div class="entry-meta">
          <div class="en">${esc(title)}</div>
          <div class="es">${esc(sub)}</div>
        </div>
      </div>`;
  }).join('');

  list.querySelectorAll('.entry-row').forEach((el) => {
    el.addEventListener('click', () => {
      state.selectedId = el.dataset.id;
      state.revealed = false;
      renderEntryList();
      renderDetail();
    });
  });
}

function fieldRow(label, value, opts) {
  opts = opts || {};
  const masked = opts.mask && !state.revealed;
  const display = masked ? '•'.repeat(Math.min(Math.max(String(value).length, 4), 24)) : value;
  const revealBtn = opts.mask ? `
    <button class="fv-reveal" title="${state.revealed ? 'Hide' : 'Reveal'}">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>
    </button>` : '';
  const copyBtn = opts.copy ? `
    <button class="fv-copy" title="Copy">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    </button>` : '';
  return `
    <div class="field-group">
      <div class="field-label">${esc(label)}</div>
      <div class="field-value${opts.wrap ? ' wrap' : ''}">
        <span class="fv-text">${esc(display)}</span>
        <div class="fv-actions">${revealBtn}${copyBtn}</div>
      </div>
    </div>`;
}

function renderDetail() {
  const pane = $('entry-detail');
  const entries = entriesForTab();
  const entry = entries.find((e) => e.id === state.selectedId);
  if (!entry) {
    pane.innerHTML = `<div class="empty-pane">Select an entry, or press Add to create one.</div>`;
    return;
  }

  const { title } = entryLabel(state.tab, entry);
  let fieldsHtml = '';
  let copyValue = null;

  if (state.tab === 'passwords') {
    fieldsHtml = fieldRow('Username', entry.username, { copy: true })
      + fieldRow('Password', entry.password, { mask: true, copy: true });
    copyValue = entry.password;
  } else if (state.tab === 'totp') {
    fieldsHtml = fieldRow('Account', entry.account, { copy: true });
    fieldsHtml += `
      <div class="field-group">
        <div class="field-label">One-time code</div>
        ${state.revealed
          ? `<div class="totp-strip" id="totp-live">
               <div class="totp-code" id="totp-code-text">------</div>
               <div class="totp-ring"><svg width="34" height="34" viewBox="0 0 34 34">
                 <circle class="bg" cx="17" cy="17" r="14" fill="none" stroke-width="3"/>
                 <circle class="fg" id="totp-ring-fg" cx="17" cy="17" r="14" fill="none" stroke-width="3" stroke-dasharray="88" stroke-dashoffset="0"/>
               </svg><div class="n" id="totp-seconds">–</div></div>
             </div>`
          : `<div class="field-value"><span class="fv-text">press reveal to show the live code</span>
               <div class="fv-actions"><button class="fv-reveal" title="Reveal"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg></button></div></div>`}
      </div>`;
  } else if (state.tab === 'ssh') {
    fieldsHtml = fieldRow('Fingerprint', entry.fingerprint, {})
      + fieldRow('Public key', entry.public_key, { copy: true, wrap: true })
      + fieldRow('Private key', entry.private_key, { mask: true, copy: true, wrap: true });
    copyValue = entry.public_key;
  } else if (state.tab === 'notes') {
    fieldsHtml = fieldRow('Body', entry.body, { mask: true, copy: true, wrap: true });
    copyValue = entry.body;
  }

  pane.innerHTML = `
    <div class="detail-head">
      <div class="avatar">${esc(initials(title))}</div>
      <div><h2>${esc(title)}</h2><div class="dsub">id ${esc(entry.id.slice(0, 8))}</div></div>
      <div class="detail-actions">
        <button class="icon-btn" id="btn-edit-entry" title="Edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></button>
        <button class="icon-btn danger" id="btn-delete-entry" title="Delete"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2m3 0-1 14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2L4 6"/></svg></button>
      </div>
    </div>
    ${fieldsHtml}
  `;

  pane.querySelectorAll('.fv-reveal').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.revealed = !state.revealed;
      renderDetail();
    });
  });
  pane.querySelectorAll('.fv-copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await invoke('copy_to_clipboard', { text: copyValue ?? '' });
        toast('Copied — clipboard clears in 30s.');
      } catch (e) {
        toast(friendlyError(e), true);
      }
    });
  });
  $('btn-edit-entry').addEventListener('click', () => openEntryModal(state.tab, entry));
  $('btn-delete-entry').addEventListener('click', () => confirmDeleteEntry(state.tab, entry));

  if (state.tab === 'totp' && state.revealed) startTotpPolling(entry.id);
}

function stopTotpPolling() {
  if (state.totpTimer) { clearInterval(state.totpTimer); state.totpTimer = null; }
}

function startTotpPolling(id) {
  stopTotpPolling();
  const tick = async () => {
    try {
      const { code, seconds_remaining } = await invoke('totp_code', { id });
      const codeEl = $('totp-code-text');
      if (!codeEl) { stopTotpPolling(); return; }
      codeEl.textContent = code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
      $('totp-seconds').textContent = `${seconds_remaining}s`;
      const period = 30;
      const frac = Math.max(0, Math.min(1, seconds_remaining / period));
      $('totp-ring-fg').setAttribute('stroke-dashoffset', String(88 * (1 - frac)));
    } catch (e) {
      stopTotpPolling();
    }
  };
  tick();
  state.totpTimer = setInterval(tick, 1000);
}

// ── Add / edit modal ────────────────────────────────────────────────────
const ENTRY_FORMS = {
  passwords: {
    title: 'Password',
    fields: [
      { key: 'name', label: 'Name', type: 'text' },
      { key: 'username', label: 'Username', type: 'text' },
      { key: 'password', label: 'Password', type: 'password', generate: true },
    ],
  },
  totp: {
    title: 'Two-Factor (TOTP)',
    fields: [
      { key: 'issuer', label: 'Issuer', type: 'text' },
      { key: 'account', label: 'Account', type: 'text' },
      { key: 'secret_base32', label: 'Secret (base32)', type: 'text', mono: true },
    ],
  },
  ssh: {
    title: 'SSH Key',
    fields: [
      { key: 'name', label: 'Name', type: 'text' },
      { key: 'public_key', label: 'Public key', type: 'textarea', mono: true },
      { key: 'private_key', label: 'Private key', type: 'textarea', mono: true },
    ],
  },
  notes: {
    title: 'Note',
    fields: [
      { key: 'title', label: 'Title', type: 'text' },
      { key: 'body', label: 'Body', type: 'textarea' },
    ],
  },
};

let modalState = { kind: null, editingId: null };

$('btn-add-entry').addEventListener('click', () => openEntryModal(state.tab, null));

function openEntryModal(kind, entry) {
  const form = ENTRY_FORMS[kind];
  modalState = { kind, editingId: entry ? entry.id : null };
  $('modal-entry-title').textContent = entry ? `Edit ${form.title}` : `Add ${form.title}`;
  $('modal-entry-error').classList.add('hidden');

  const valueFor = (key) => {
    if (!entry) return '';
    if (key === 'secret_base32') return ''; // secret is never sent back plaintext-base32 by the backend; re-enter to change
    return entry[key] ?? '';
  };

  $('modal-entry-body').innerHTML = form.fields.map((f) => {
    const val = esc(valueFor(f.key));
    const monoStyle = f.mono ? ' style="font-family: var(--font-mono); font-size: 12px;"' : '';
    if (f.type === 'textarea') {
      return `<textarea class="field" id="mf-${f.key}" placeholder="${esc(f.label)}"${monoStyle}>${val}</textarea>`;
    }
    if (f.generate) {
      return `
        <div class="gen-row">
          <input class="field" id="mf-${f.key}" type="text" placeholder="${esc(f.label)}" value="${val}"${monoStyle} />
          <button class="gen-btn" id="mf-generate" type="button">Generate</button>
        </div>`;
    }
    return `<input class="field" id="mf-${f.key}" type="text" placeholder="${esc(f.label)}" value="${val}"${monoStyle} />`;
  }).join('');

  const genBtn = $('mf-generate');
  if (genBtn) {
    genBtn.addEventListener('click', async () => {
      const pw = await invoke('generate_password', { length: 20 });
      $('mf-password').value = pw;
    });
  }

  $('modal-entry').classList.remove('hidden');
}

$('modal-entry-close').addEventListener('click', closeEntryModal);
$('modal-entry-cancel').addEventListener('click', closeEntryModal);
function closeEntryModal() { $('modal-entry').classList.add('hidden'); }

$('modal-entry-save').addEventListener('click', async () => {
  const form = ENTRY_FORMS[modalState.kind];
  const values = {};
  for (const f of form.fields) {
    values[f.key] = $(`mf-${f.key}`).value;
  }
  const err = $('modal-entry-error');
  err.classList.add('hidden');

  const isEdit = !!modalState.editingId;
  for (const f of form.fields) {
    if (values[f.key]) continue;
    const label = f.key === 'secret_base32' && isEdit ? 'Re-enter the secret to save changes' : `${f.label} is required.`;
    err.textContent = label;
    err.classList.remove('hidden');
    return;
  }

  try {
    let blob;
    if (modalState.kind === 'passwords') {
      blob = isEdit
        ? await invoke('update_password', { id: modalState.editingId, ...values })
        : await invoke('add_password', values);
    } else if (modalState.kind === 'totp') {
      blob = isEdit
        ? await invoke('update_totp', { id: modalState.editingId, ...values })
        : await invoke('add_totp', values);
    } else if (modalState.kind === 'ssh') {
      blob = isEdit
        ? await invoke('update_ssh_key', { id: modalState.editingId, ...values })
        : await invoke('add_ssh_key', values);
    } else if (modalState.kind === 'notes') {
      blob = isEdit
        ? await invoke('update_note', { id: modalState.editingId, ...values })
        : await invoke('add_note', values);
    }
    state.blob = blob;
    closeEntryModal();
    if (isEdit) state.selectedId = modalState.editingId;
    renderEntryList();
    renderDetail();
    toast('Saved.');
    if (modalState.kind === 'ssh') refreshSshStatus();
  } catch (e) {
    err.textContent = friendlyError(e);
    err.classList.remove('hidden');
  }
});

function refreshSshStatus() {
  invoke('ssh_agent_status').then((s) => { $('settings-ssh-status').textContent = s || 'not running'; }).catch(() => {});
}

// ── Confirm modal (delete) ───────────────────────────────────────────────
const KIND_KEY = { passwords: 'password', totp: 'totp', ssh: 'ssh', notes: 'note' };

function confirmDeleteEntry(tab, entry) {
  const { title } = entryLabel(tab, entry);
  $('modal-confirm-title').textContent = 'Delete entry?';
  $('modal-confirm-body').textContent = `"${title}" will be permanently deleted. This cannot be undone.`;
  state.confirmAction = async () => {
    try {
      const blob = await invoke('delete_entry', { kind: KIND_KEY[tab], id: entry.id });
      state.blob = blob;
      state.selectedId = null;
      renderEntryList();
      renderDetail();
      toast('Deleted.');
      if (tab === 'ssh') refreshSshStatus();
    } catch (e) {
      toast(friendlyError(e), true);
    }
  };
  $('modal-confirm').classList.remove('hidden');
}

$('modal-confirm-close').addEventListener('click', closeConfirmModal);
$('modal-confirm-cancel').addEventListener('click', closeConfirmModal);
function closeConfirmModal() { $('modal-confirm').classList.add('hidden'); state.confirmAction = null; }

$('modal-confirm-ok').addEventListener('click', async () => {
  const action = state.confirmAction;
  closeConfirmModal();
  if (action) await action();
});

// ── Security panel ────────────────────────────────────────────────────
function renderSecurity() {
  const h = state.header;
  if (!h) { $('security-grid').innerHTML = ''; return; }

  const kdfDetail = h.kdf_algorithm === 'Argon2id'
    ? `${h.argon2_memory_kib / 1024} MiB · ${h.kdf_time_cost} passes · ${h.argon2_parallelism} lanes`
    : `${h.kdf_time_cost.toLocaleString()} iterations`;

  const cards = [
    { label: 'Vault format', pillClass: 'on2', pill: `v${h.format_version}`, value: 'FOB2', detail: 'On-disk vault format.' },
    { label: 'Key derivation', pillClass: 'on', pill: h.kdf_algorithm, value: kdfDetail, detail: h.kdf_algorithm === 'Argon2id' ? 'Memory-hard — raises the cost of offline brute-force well above PBKDF2.' : 'Legacy/browser-compatible KDF.' },
    { label: 'Encryption', pillClass: '', pill: '', value: 'AES-256-GCM', detail: 'Authenticated per vault slot, keyed via HKDF-SHA256.' },
    {
      label: 'Recovery key',
      pillClass: h.recovery_enabled ? 'on' : 'off',
      pill: h.recovery_enabled ? 'Enabled' : 'Disabled',
      value: h.recovery_enabled ? 'X25519 + ML-KEM-1024' : 'Not configured',
      detail: h.recovery_enabled
        ? 'Hybrid post-quantum wrap of the master secret. Unlocks the vault without your passphrase.'
        : 'This vault was created without a recovery key — a lost passphrase means the contents are unrecoverable.',
    },
  ];

  $('security-grid').innerHTML = cards.map((c) => `
    <div class="sec-card">
      <div class="sc-top">
        <span class="sc-label">${esc(c.label)}</span>
        ${c.pill ? `<span class="sec-pill ${c.pillClass}">${esc(c.pill)}</span>` : ''}
      </div>
      <div class="sc-value">${esc(c.value)}</div>
      <div class="sc-detail">${esc(c.detail)}</div>
    </div>
  `).join('');
}

// ── Boot ────────────────────────────────────────────────────────────────
boot();
