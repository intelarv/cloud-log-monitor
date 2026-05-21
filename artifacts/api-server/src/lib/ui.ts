// Embedded single-file HTML dashboard. We embed it as a TS constant so the
// esbuild bundle is self-contained (no public/ copy step in build.mjs).
export const UI_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>PHI Audit — M0</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; }
    .scroll { overflow-y: auto; }
    .citation { background: #fef9c3; border-bottom: 1px dotted #ca8a04; cursor: pointer; padding: 0 2px; border-radius: 2px; }
    .sev-critical { background:#fecaca; color:#7f1d1d; }
    .sev-high     { background:#fed7aa; color:#7c2d12; }
    .sev-medium   { background:#fef08a; color:#713f12; }
    .sev-low      { background:#bbf7d0; color:#14532d; }
  </style>
</head>
<body class="bg-slate-100 text-slate-900 h-screen">
  <div id="root" class="flex flex-col h-screen">
    <header class="bg-slate-900 text-slate-100 px-4 py-2 flex items-center justify-between border-b border-slate-800">
      <div class="font-semibold tracking-tight">PHI/PII Audit <span class="text-slate-400 font-normal">— M0 walking skeleton</span></div>
      <div id="user-area" class="text-sm flex items-center gap-3"></div>
    </header>
    <main class="grid grid-cols-12 flex-1 min-h-0">
      <aside class="col-span-3 border-r border-slate-200 bg-white flex flex-col min-h-0">
        <div class="px-3 py-2 border-b border-slate-200 flex items-center justify-between">
          <h2 class="font-medium">Findings</h2>
          <button id="refresh-findings" class="text-xs text-slate-500 hover:text-slate-900">refresh</button>
        </div>
        <div id="findings-list" class="scroll flex-1 divide-y divide-slate-100 text-sm"></div>
      </aside>
      <section class="col-span-6 flex flex-col min-h-0 bg-slate-50">
        <div class="px-3 py-2 border-b border-slate-200 flex items-center gap-2 bg-white">
          <h2 class="font-medium">Chat</h2>
          <select id="session-select" class="border border-slate-300 rounded px-1 py-0.5 text-xs"></select>
          <button id="new-session" class="text-xs px-2 py-0.5 bg-slate-900 text-white rounded">new</button>
          <span id="agent-status" class="text-xs text-slate-500 ml-auto"></span>
        </div>
        <div id="messages" class="scroll flex-1 p-3 space-y-3"></div>
        <form id="chat-form" class="border-t border-slate-200 p-2 bg-white flex gap-2">
          <input id="chat-input" type="text" placeholder="Ask about a finding..." autocomplete="off"
            class="flex-1 border border-slate-300 rounded px-2 py-1" />
          <button class="bg-slate-900 text-white px-3 py-1 rounded text-sm">Send</button>
        </form>
      </section>
      <aside class="col-span-3 border-l border-slate-200 bg-white flex flex-col min-h-0">
        <div class="px-3 py-2 border-b border-slate-200 flex items-center justify-between">
          <h2 class="font-medium">Evidence</h2>
          <a href="#" id="open-ledger" class="text-xs text-slate-500 hover:text-slate-900">ledger ↗</a>
        </div>
        <div id="evidence" class="scroll flex-1 p-3 text-sm text-slate-600">Select a finding or click a citation in chat.</div>
      </aside>
    </main>
    <div id="ledger-modal" class="hidden fixed inset-0 bg-slate-900/50 z-30 items-center justify-center">
      <div class="bg-white rounded shadow-lg w-[80vw] max-w-4xl h-[80vh] flex flex-col">
        <div class="px-4 py-2 border-b flex items-center justify-between">
          <div><span class="font-semibold">Ledger</span> <span id="ledger-head" class="ml-3 text-xs text-slate-500"></span></div>
          <div class="flex items-center gap-3">
            <button id="ledger-verify" class="text-xs px-2 py-1 bg-slate-100 rounded">verify chain</button>
            <button id="ledger-close" class="text-xs px-2 py-1 bg-slate-900 text-white rounded">close</button>
          </div>
        </div>
        <div id="ledger-list" class="scroll flex-1 text-xs font-mono p-3"></div>
      </div>
    </div>
  </div>
  <div id="login-overlay" class="hidden fixed inset-0 bg-slate-900/70 z-40 items-center justify-center">
    <form id="login-form" class="bg-white rounded shadow p-6 w-80 space-y-3">
      <h2 class="font-semibold">Sign in (M0 dev)</h2>
      <input name="username" placeholder="username" class="w-full border border-slate-300 rounded px-2 py-1" value="analyst" />
      <input name="tenant_id" placeholder="tenant" class="w-full border border-slate-300 rounded px-2 py-1" value="default" />
      <button class="w-full bg-slate-900 text-white py-1 rounded">Sign in</button>
    </form>
  </div>
<script>
const API = "/api";
let session = null;
let currentSessionId = null;
let findingsById = {};

async function api(path, opts) {
  const res = await fetch(API + path, Object.assign({ credentials: 'include' }, opts || {}));
  if (res.status === 401) {
    showLogin();
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(res.status + ': ' + text);
  }
  return res;
}

function showLogin() {
  document.getElementById('login-overlay').classList.remove('hidden');
  document.getElementById('login-overlay').classList.add('flex');
}
function hideLogin() {
  document.getElementById('login-overlay').classList.add('hidden');
  document.getElementById('login-overlay').classList.remove('flex');
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch(API + '/auth/login', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: fd.get('username'), tenant_id: fd.get('tenant_id') })
  });
  if (r.ok) { session = await r.json(); hideLogin(); init(); }
});

async function loadMe() {
  try { const r = await fetch(API + '/me', { credentials: 'include' }); if (r.ok) session = await r.json(); }
  catch (e) { /* ignore */ }
}

function renderUserArea() {
  const el = document.getElementById('user-area');
  if (!session) { el.innerHTML = ''; return; }
  el.innerHTML = '<span class="text-slate-400">' + session.tenant_id + '</span> · <span>' + session.sub + '</span> · <button id="logout-btn" class="text-slate-300 hover:text-white underline">logout</button>';
  document.getElementById('logout-btn').addEventListener('click', async () => {
    await fetch(API + '/auth/logout', { method: 'POST', credentials: 'include' });
    session = null; showLogin();
  });
}

function sevBadge(sev) { return '<span class="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded sev-' + sev + '">' + sev + '</span>'; }

async function loadFindings() {
  const r = await api('/findings');
  const items = await r.json();
  findingsById = {};
  for (const f of items) findingsById[f.id] = f;
  const list = document.getElementById('findings-list');
  list.innerHTML = items.map(f => (
    '<div class="px-3 py-2 cursor-pointer hover:bg-slate-50" data-fid="' + f.id + '">' +
      '<div class="flex items-center justify-between"><span class="font-mono text-xs text-slate-500">' + f.id + '</span>' + sevBadge(f.severity) + '</div>' +
      '<div class="text-sm font-medium mt-0.5">' + f.classification + (f.subclass ? ' / ' + f.subclass : '') + '</div>' +
      '<div class="text-xs text-slate-500 mt-0.5">' + f.source + '</div>' +
    '</div>'
  )).join('');
  list.querySelectorAll('[data-fid]').forEach(el => el.addEventListener('click', () => showEvidence(el.dataset.fid)));
}

function showEvidence(id) {
  const f = findingsById[id];
  const el = document.getElementById('evidence');
  if (!f) { el.textContent = id + ' not loaded (try refresh).'; return; }
  const ev = f.redacted_evidence || {};
  el.innerHTML =
    '<div class="space-y-2">' +
      '<div class="flex items-center gap-2"><span class="font-mono text-xs text-slate-500">' + f.id + '</span>' + sevBadge(f.severity) + '</div>' +
      '<div class="font-medium">' + f.classification + (f.subclass ? ' / ' + f.subclass : '') + '</div>' +
      '<div class="text-xs text-slate-500">source: ' + f.source + '</div>' +
      '<div class="text-xs text-slate-500">detector: ' + f.detector_version + '</div>' +
      '<div class="text-xs text-slate-500">fingerprint: <span class="font-mono">' + f.fingerprint + '</span></div>' +
      '<div class="mt-2 p-2 bg-slate-100 rounded font-mono text-xs whitespace-pre-wrap">' + escapeHtml(ev.snippet || '') + '</div>' +
      '<div class="text-xs text-slate-500">trust: ' + (ev.trust || 'untrusted') + ' · redactions: ' + (ev.redactions || []).join(', ') + '</div>' +
    '</div>';
}

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"})[c]); }

function renderCitations(text) {
  return escapeHtml(text).replace(/\\[F:([A-Za-z0-9_-]+)\\]/g, (_, id) => '<span class="citation" data-cite="' + id + '">[F:' + id + ']</span>');
}

async function loadSessions() {
  const r = await api('/chat/sessions');
  const sessions = await r.json();
  const sel = document.getElementById('session-select');
  sel.innerHTML = sessions.map(s => '<option value="' + s.id + '">' + (s.title || s.id.slice(0,12)) + '</option>').join('');
  if (sessions.length === 0) await newSession();
  else { currentSessionId = sel.value; await loadMessages(); }
}

async function newSession() {
  const r = await api('/chat/sessions', { method:'POST', headers:{ 'Content-Type':'application/json' }, body: JSON.stringify({}) });
  const s = await r.json();
  await loadSessions();
  document.getElementById('session-select').value = s.id;
  currentSessionId = s.id;
  await loadMessages();
}

async function loadMessages() {
  const r = await api('/chat/sessions/' + currentSessionId + '/messages');
  const msgs = await r.json();
  const el = document.getElementById('messages');
  el.innerHTML = msgs.map(renderMessage).join('');
  bindCitations();
  el.scrollTop = el.scrollHeight;
}

function renderMessage(m) {
  const isUser = m.role === 'user';
  const align = isUser ? 'justify-end' : 'justify-start';
  const bubble = isUser
    ? 'bg-slate-900 text-white'
    : 'bg-white border border-slate-200';
  return '<div class="flex ' + align + '"><div class="max-w-[80%] rounded px-3 py-2 ' + bubble + '">' +
    '<div class="text-xs opacity-60 mb-0.5">' + (isUser ? 'you' : (m.agent_identity ? m.agent_identity.agent + '@' + m.agent_identity.agent_version : 'agent')) + '</div>' +
    '<div class="text-sm whitespace-pre-wrap" data-msg="' + m.id + '">' + renderCitations(m.content || '') + '</div>' +
  '</div></div>';
}

function bindCitations() {
  document.querySelectorAll('[data-cite]').forEach(el => {
    el.addEventListener('click', () => showEvidence(el.dataset.cite));
  });
}

document.getElementById('chat-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('chat-input');
  const content = input.value.trim();
  if (!content || !currentSessionId) return;
  input.value = '';
  await streamChat(content);
});

async function streamChat(content) {
  const status = document.getElementById('agent-status');
  status.textContent = 'thinking...';
  const messages = document.getElementById('messages');
  const userDiv = document.createElement('div');
  userDiv.innerHTML = renderMessage({ id: 'tmp-u', role: 'user', content, agent_identity: null });
  messages.appendChild(userDiv);
  const agentDiv = document.createElement('div');
  agentDiv.innerHTML = renderMessage({ id: 'tmp-a', role: 'assistant', content: '', agent_identity: null });
  messages.appendChild(agentDiv);
  const agentTextEl = agentDiv.querySelector('[data-msg]');
  messages.scrollTop = messages.scrollHeight;
  let buf = '';
  let agentBuf = '';
  const res = await fetch(API + '/chat/sessions/' + currentSessionId + '/messages', {
    method: 'POST', credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
    body: JSON.stringify({ content })
  });
  if (!res.ok || !res.body) { status.textContent = 'error'; return; }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\\n\\n')) >= 0) {
      const raw = buf.slice(0, idx); buf = buf.slice(idx + 2);
      const lines = raw.split('\\n');
      let data = '';
      for (const ln of lines) if (ln.startsWith('data:')) data += ln.slice(5).trim();
      if (!data) continue;
      let ev; try { ev = JSON.parse(data); } catch { continue; }
      if (ev.type === 'agent_message_delta') {
        agentBuf += ev.delta;
        agentTextEl.innerHTML = renderCitations(agentBuf);
        bindCitations();
        messages.scrollTop = messages.scrollHeight;
      } else if (ev.type === 'tool_call') {
        status.textContent = 'calling tool ' + ev.tool + '...';
      } else if (ev.type === 'tool_result') {
        status.textContent = 'tool ' + (ev.ok ? 'ok' : 'failed');
      } else if (ev.type === 'agent_message_complete') {
        status.textContent = 'done · cites: ' + (ev.citations || []).join(', ');
      } else if (ev.type === 'error') {
        agentBuf += '\\n[error: ' + ev.error + ']';
        agentTextEl.textContent = agentBuf;
      } else if (ev.type === 'done') {
        status.textContent = '';
      }
    }
  }
  await loadFindings();
}

// Ledger modal
async function openLedger() {
  const modal = document.getElementById('ledger-modal');
  modal.classList.remove('hidden'); modal.classList.add('flex');
  const r = await fetch(API + '/ledger?limit=200', { credentials: 'include' });
  const page = await r.json();
  document.getElementById('ledger-head').textContent = 'head_seq=' + page.head_seq + ' head_hash=' + page.head_hash.slice(0,16) + '…';
  document.getElementById('ledger-list').innerHTML = page.entries.map(e =>
    '<div class="border-b border-slate-100 py-1"><span class="text-slate-400">#' + e.seq + '</span> ' +
    '<span class="text-slate-600">' + e.event_type + '</span>' +
    (e.subject_id ? ' <span class="text-slate-500">' + e.subject_type + '=' + e.subject_id + '</span>' : '') +
    ' <span class="text-slate-400">' + new Date(e.ts).toLocaleTimeString() + '</span>' +
    ' <div class="text-slate-400 ml-4 truncate">hash=' + e.hash.slice(0,16) + '… prev=' + e.prev_hash.slice(0,8) + '…</div>' +
    '</div>'
  ).join('');
}
document.getElementById('open-ledger').addEventListener('click', (e) => { e.preventDefault(); openLedger(); });
document.getElementById('ledger-close').addEventListener('click', () => {
  const m = document.getElementById('ledger-modal');
  m.classList.add('hidden'); m.classList.remove('flex');
});
document.getElementById('ledger-verify').addEventListener('click', async () => {
  const r = await fetch(API + '/admin/ledger/verify', { credentials: 'include' });
  const v = await r.json();
  alert('ok=' + v.ok + ' walked=' + v.walked + ' head_seq=' + v.head_seq + (v.errors.length ? '\\nerrors:\\n' + v.errors.join('\\n') : ''));
});

document.getElementById('refresh-findings').addEventListener('click', loadFindings);
document.getElementById('new-session').addEventListener('click', newSession);
document.getElementById('session-select').addEventListener('change', async (e) => { currentSessionId = e.target.value; await loadMessages(); });

async function init() {
  renderUserArea();
  await loadFindings();
  await loadSessions();
}

(async () => {
  await loadMe();
  if (!session) showLogin();
  else init();
})();
</script>
</body>
</html>`;
