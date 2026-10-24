(() => {
  'use strict';

  // ---------- helpers ----------
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (v) =>
    String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtSize = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
  const fmtDate = (d) => new Date(d).toLocaleString();

  let token = sessionStorage.getItem('tv_token');
  let me = null;
  let docs = [];
  let shareDocId = null;
  let auditOffset = 0;
  const AUDIT_PAGE = 25;

  function toast(msg, ok = true) {
    const el = $('#toast');
    el.textContent = msg;
    el.className = `fixed top-4 right-4 z-50 max-w-sm rounded-lg px-4 py-3 text-sm shadow-lg ${ok ? 'bg-emerald-600 text-white' : 'bg-red-600 text-white'}`;
    clearTimeout(toast.t);
    toast.t = setTimeout(() => el.classList.add('hidden'), 4000);
  }

  async function api(path, { method = 'GET', body, form, raw = false } = {}) {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    let payload;
    if (form) payload = form;
    else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }

    const res = await fetch(`/api${path}`, { method, headers, body: payload });
    if (res.status === 401 && token && path !== '/auth/login') { logout(); throw new Error('Session expired - please sign in again'); }
    if (raw) return res;

    let data = null;
    try { data = await res.json(); } catch (_) { /* no body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // ---------- auth / views ----------
  function setAuthMode(mode) {
    const reg = mode === 'register';
    $('#loginForm').classList.toggle('hidden', reg);
    $('#registerForm').classList.toggle('hidden', !reg);
    $('#toggleToRegister').classList.toggle('hidden', reg);
    $('#toggleToLogin').classList.toggle('hidden', !reg);
    $('#loginError').classList.add('hidden');
    $('#loginNotice').classList.add('hidden');
    $('#registerError').classList.add('hidden');
  }

  function show(view) {
    $('#loginView').classList.toggle('hidden', view !== 'login');
    $('#appView').classList.toggle('hidden', view !== 'app');
  }

  function logout() {
    token = null; me = null; docs = [];
    sessionStorage.removeItem('tv_token');
    show('login');
  }

  async function enterApp() {
    try {
      me = (await api('/auth/me')).user;
    } catch (_) { return logout(); }
    $('#whoami').textContent = `${me.email} (${me.role})`;
    $('#tabAdmin').classList.toggle('hidden', me.role !== 'ADMIN'); // UI hint only; server enforces
    show('app');
    switchTab('docs');
    return loadDocs();
  }

  function switchTab(tab) {
    const isDocs = tab === 'docs';
    $('#docsPanel').classList.toggle('hidden', !isDocs);
    $('#adminPanel').classList.toggle('hidden', isDocs);
    $('#tabDocs').className = `rounded-md px-3 py-1.5 ${isDocs ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'}`;
    $('#tabAdmin').className = `${me && me.role === 'ADMIN' ? '' : 'hidden '}rounded-md px-3 py-1.5 ${!isDocs ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'}`;
    if (!isDocs) { auditOffset = 0; loadAdmin(); }
  }

  // ---------- documents ----------
  async function loadDocs() {
    try { docs = (await api('/documents')).documents; renderDocs(); }
    catch (e) { toast(e.message, false); }
  }

  function renderDocs() {
    const body = $('#docRows');
    if (!docs.length) {
      body.innerHTML = '<tr><td colspan="5" class="px-4 py-8 text-center text-slate-500">No documents yet.</td></tr>';
      return;
    }
    body.innerHTML = docs.map((d) => {
      const manage = d.accessLevel === 'OWNER' || d.accessLevel === 'ADMIN';
      return `<tr class="hover:bg-slate-900/60">
        <td class="px-4 py-3"><div class="font-medium">${esc(d.title)}</div><div class="text-xs text-slate-500">${esc(d.originalName)}${d.description ? ' - ' + esc(d.description) : ''}</div></td>
        <td class="px-4 py-3 text-slate-300">${esc(d.owner && d.owner.email)}</td>
        <td class="px-4 py-3"><span class="rounded-full bg-slate-800 px-2 py-0.5 text-xs">${esc(d.accessLevel)}</span>${d.isPublic ? ' <span class="rounded-full bg-sky-900 px-2 py-0.5 text-xs text-sky-300">public</span>' : ''}</td>
        <td class="px-4 py-3 text-slate-400">${fmtSize(d.size)}</td>
        <td class="px-4 py-3 text-right whitespace-nowrap">
          <button data-action="download" data-id="${esc(d.id)}" class="rounded-md bg-slate-800 px-3 py-1 text-xs hover:bg-slate-700">Download</button>
          ${manage ? `<button data-action="share" data-id="${esc(d.id)}" class="ml-1 rounded-md bg-slate-800 px-3 py-1 text-xs hover:bg-slate-700">Share</button>
          <button data-action="delete" data-id="${esc(d.id)}" class="ml-1 rounded-md bg-red-900/60 px-3 py-1 text-xs text-red-200 hover:bg-red-800">Delete</button>` : ''}
        </td></tr>`;
    }).join('');
  }

  async function downloadDoc(id) {
    try {
      const res = await api(`/documents/${encodeURIComponent(id)}/download`, { raw: true });
      if (res.status === 403) return toast('403 Forbidden - you no longer have access (attempt was audited).', false);
      if (!res.ok) return toast(`Download failed (${res.status})`, false);
      const doc = docs.find((d) => d.id === id);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = doc ? doc.originalName : 'download';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { toast(e.message, false); }
  }

  async function deleteDoc(id) {
    if (!window.confirm('Delete this document? This cannot be undone.')) return;
    try { await api(`/documents/${encodeURIComponent(id)}`, { method: 'DELETE' }); toast('Document deleted'); await loadDocs(); }
    catch (e) { toast(e.message, false); }
  }

  // ---------- modals ----------
  const openModal = (id) => { const m = $(id); m.classList.remove('hidden'); m.classList.add('flex'); };
  function closeModals() {
    for (const id of ['#uploadModal', '#shareModal']) { $(id).classList.add('hidden'); $(id).classList.remove('flex'); }
  }

  async function openShare(id) {
    shareDocId = id;
    $('#grantEmail').value = '';
    openModal('#shareModal');
    await refreshShare();
  }

  async function refreshShare() {
    const list = $('#grantList');
    try {
      const data = await api(`/documents/${encodeURIComponent(shareDocId)}`);
      $('#shareTitle').textContent = data.document.title;
      const perms = data.permissions || [];
      list.innerHTML = perms.length
        ? perms.map((p) => `<li class="flex items-center justify-between py-2"><div><div>${esc(p.email)}</div><div class="text-xs text-slate-500">${esc(p.name)} - ${esc(p.level)}</div></div>
            <button data-action="revoke" data-user="${esc(p.userId)}" class="rounded-md bg-red-900/60 px-3 py-1 text-xs text-red-200 hover:bg-red-800">Revoke</button></li>`).join('')
        : '<li class="py-3 text-slate-500">No one else has access.</li>';
    } catch (e) { list.innerHTML = ''; toast(e.message, false); }
  }

  // ---------- admin ----------
  async function loadAdmin() {
    try {
      const s = await api('/admin/system-stats');
      const cards = [
        ['Users', s.users], ['Documents', s.documents], ['Audit events', s.auditEvents],
        ['Allowed', s.allowed], ['Denied', s.denied], ['Denied (24h)', s.deniedLast24h],
      ];
      $('#statCards').innerHTML = cards.map(([k, v]) =>
        `<div class="rounded-xl border border-slate-800 bg-slate-900 p-4"><div class="text-xs text-slate-400">${esc(k)}</div><div class="mt-1 text-2xl font-semibold">${esc(v)}</div></div>`).join('');
      await loadAudit();
    } catch (e) { toast(e.message, false); }
  }

  async function loadAudit() {
    const q = new URLSearchParams({ limit: String(AUDIT_PAGE), offset: String(auditOffset) });
    if ($('#fStatus').value) q.set('status', $('#fStatus').value);
    if ($('#fAction').value.trim()) q.set('action', $('#fAction').value.trim());
    if ($('#fUser').value.trim()) q.set('userEmail', $('#fUser').value.trim());
    try {
      const data = await api(`/admin/audit-logs?${q}`);
      $('#auditRows').innerHTML = data.logs.map((l) => `<tr>
        <td class="px-3 py-2 whitespace-nowrap text-slate-400">${esc(fmtDate(l.createdAt))}</td>
        <td class="px-3 py-2">${esc(l.userEmail || '-')}</td>
        <td class="px-3 py-2 font-mono">${esc(l.action)}</td>
        <td class="px-3 py-2"><span class="rounded-full px-2 py-0.5 ${l.status === 'ALLOWED' ? 'bg-emerald-900 text-emerald-300' : 'bg-red-900 text-red-300'}">${esc(l.status)}</span></td>
        <td class="px-3 py-2 font-mono text-slate-400">${esc(l.documentId || '-')}</td>
        <td class="px-3 py-2 text-slate-400">${esc(l.ipAddress || '-')}</td>
        <td class="px-3 py-2 text-slate-400">${esc(l.details || '')}</td></tr>`).join('')
        || '<tr><td colspan="7" class="px-3 py-6 text-center text-slate-500">No matching events.</td></tr>';
      const end = Math.min(auditOffset + AUDIT_PAGE, data.total);
      $('#auditCount').textContent = data.total ? `${auditOffset + 1}-${end} of ${data.total}` : '0 events';
      auditTotal = data.total;
    } catch (e) { toast(e.message, false); }
  }
  let auditTotal = 0;

  // ---------- events ----------
  document.addEventListener('click', (ev) => {
    const el = ev.target.closest('[data-action]');
    if (!el) return;
    const { action, id, user, tab } = el.dataset;
    switch (action) {
      case 'logout': logout(); break;
      case 'show-register': setAuthMode('register'); break;
      case 'show-login': setAuthMode('login'); break;
      case 'tab': switchTab(tab); break;
      case 'open-upload': $('#uploadForm').reset(); openModal('#uploadModal'); break;
      case 'close-modal': closeModals(); break;
      case 'download': downloadDoc(id); break;
      case 'delete': deleteDoc(id); break;
      case 'share': openShare(id); break;
      case 'revoke':
        api(`/documents/${encodeURIComponent(shareDocId)}/permissions/${encodeURIComponent(user)}`, { method: 'DELETE' })
          .then(() => { toast('Access revoked'); return refreshShare(); })
          .catch((e) => toast(e.message, false));
        break;
      case 'audit-prev': if (auditOffset > 0) { auditOffset = Math.max(0, auditOffset - AUDIT_PAGE); loadAudit(); } break;
      case 'audit-next': if (auditOffset + AUDIT_PAGE < auditTotal) { auditOffset += AUDIT_PAGE; loadAudit(); } break;
      default: break;
    }
  });

  $('#loginForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const err = $('#loginError');
    err.classList.add('hidden');
    try {
      const data = await api('/auth/login', { method: 'POST', body: { email: $('#loginEmail').value, password: $('#loginPassword').value } });
      token = data.token;
      sessionStorage.setItem('tv_token', token);
      $('#loginPassword').value = '';
      await enterApp();
    } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
  });

  $('#registerForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const err = $('#registerError');
    err.classList.add('hidden');
    const email = $('#regEmail').value.trim();
    try {
      await api('/auth/register', {
        method: 'POST',
        body: { name: $('#regName').value, email, password: $('#regPassword').value },
      });
      $('#registerForm').reset();
      setAuthMode('login');
      $('#loginEmail').value = email;
      $('#loginPassword').value = '';
      const notice = $('#loginNotice');
      notice.textContent = 'Account created. Please sign in.';
      notice.classList.remove('hidden');
      $('#loginPassword').focus();
    } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
  });

  $('#uploadForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const file = $('#upFile').files[0];
    if (!file) return;
    const fd = new FormData();
    fd.append('title', $('#upTitle').value);
    fd.append('description', $('#upDesc').value);
    fd.append('isPublic', $('#upPublic').checked ? 'true' : 'false');
    fd.append('file', file);
    try { await api('/documents/upload', { method: 'POST', form: fd }); closeModals(); toast('Document uploaded'); await loadDocs(); }
    catch (e) { toast(e.message, false); }
  });

  $('#grantForm').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api(`/documents/${encodeURIComponent(shareDocId)}/permissions`, {
        method: 'POST', body: { email: $('#grantEmail').value, level: $('#grantLevel').value },
      });
      $('#grantEmail').value = '';
      toast('Access granted');
      await refreshShare();
    } catch (e) { toast(e.message, false); }
  });

  $('#auditFilters').addEventListener('submit', (ev) => { ev.preventDefault(); auditOffset = 0; loadAudit(); });

  // ---------- boot ----------
  if (token) enterApp(); else show('login');
})();
