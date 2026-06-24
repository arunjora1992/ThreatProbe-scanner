/* Single-page application logic. Framework-free. */
(() => {
  const view = document.getElementById("view");
  let pollTimer = null;

  // ---------- helpers ----------
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
  const sevBadge = (s) => `<span class="badge sev-${esc(s || "UNKNOWN")}">${esc(s || "UNKNOWN")}</span>`;
  const statusBadge = (s) => `<span class="status-badge status-${esc(s)}">${esc(s)}</span>`;
  const fmtDate = (d) => d ? new Date(d).toLocaleString() : "—";

  // ---------- inline SVG icon set (framework-free, CSP-safe, air-gap friendly) ----------
  const ICONS = {
    dashboard: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
    targets: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/>',
    scans: '<circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    schedules: '<rect x="3" y="4.5" width="18" height="16.5" rx="2"/><line x1="16" y1="2.5" x2="16" y2="6.5"/><line x1="8" y1="2.5" x2="8" y2="6.5"/><line x1="3" y1="10" x2="21" y2="10"/>',
    cves: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M20 5v14c0 1.66-3.58 3-8 3s-8-1.34-8-3V5"/><path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/>',
    reports: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/>',
    settings: '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1.5" y1="14" x2="6.5" y2="14"/><line x1="9.5" y1="8" x2="14.5" y2="8"/><line x1="17.5" y1="16" x2="22.5" y2="16"/>',
    users: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
    about: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="11.5"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    activity: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    alert: '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13.5"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    flame: '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>',
    server: '<rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><line x1="6" y1="7" x2="6.01" y2="7"/><line x1="6" y1="17" x2="6.01" y2="17"/>',
    assistant: '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8z"/>',
    send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
    close: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  };
  function icon(name, cls) {
    return `<svg class="ic ${cls || ""}" viewBox="0 0 24 24" fill="none" stroke="currentColor" `
      + `stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">`
      + `${ICONS[name] || ICONS.activity}</svg>`;
  }
  // Standard page header: gradient icon chip + title + optional right-aligned actions HTML.
  function pageHead(name, title, right) {
    return `<div class="page-head">`
      + `<div class="ph-title"><span class="ph-icon">${icon(name)}</span><h1>${title}</h1></div>`
      + (right ? `<div class="ph-actions">${right}</div>` : "")
      + `</div>`;
  }
  const NAV_LABELS = { dashboard: "Dashboard", targets: "Targets", scans: "Scans",
    schedules: "Schedules", cves: "CVE Database", reports: "Reports",
    settings: "Settings", users: "Users", about: "About" };
  function applyNavIcons() {
    document.querySelectorAll(".nav-item").forEach((el) => {
      const r = el.dataset.route;
      if (NAV_LABELS[r]) el.innerHTML = icon(r, "nav-ic") + `<span>${NAV_LABELS[r]}</span>`;
    });
  }

  // ---------- inline SVG charts (framework-free, CSP-safe) ----------
  const SEV_COLOR = { CRITICAL: "#be123c", HIGH: "#ef4444", MEDIUM: "#f59e0b",
                      LOW: "#3b82f6", INFO: "#64748b", NONE: "#64748b", UNKNOWN: "#64748b" };
  // Donut from segments [{value,color}], with a centre label. Pure SVG via stroke-dasharray.
  function svgDonut(segments, centerTop, centerBot) {
    const total = segments.reduce((a, s) => a + s.value, 0) || 1;
    const R = 52, C = 2 * Math.PI * R;
    let off = 0;
    const rings = segments.filter(s => s.value > 0).map((s) => {
      const len = (s.value / total) * C;
      const seg = `<circle cx="70" cy="70" r="${R}" fill="none" stroke="${s.color}" stroke-width="16"
        stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}"
        transform="rotate(-90 70 70)"></circle>`;
      off += len; return seg;
    }).join("");
    return `<svg width="140" height="140" viewBox="0 0 140 140" role="img">
      <circle cx="70" cy="70" r="${R}" fill="none" stroke="var(--border)" stroke-width="16"></circle>
      ${rings}
      <text x="70" y="66" text-anchor="middle" font-size="26" font-weight="700" fill="currentColor">${esc(centerTop)}</text>
      <text x="70" y="86" text-anchor="middle" font-size="11" fill="var(--muted)">${esc(centerBot || "")}</text>
    </svg>`;
  }
  // Horizontal bar chart from items [{label,value,color}].
  function svgBars(items) {
    const max = Math.max(1, ...items.map(i => i.value));
    return `<div class="bars">` + items.map((i) => `
      <div class="bar-row"><span class="bar-lbl">${esc(i.label)}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${(i.value / max * 100).toFixed(1)}%;background:${i.color}"></span></span>
        <span class="bar-val">${i.value}</span></div>`).join("") + `</div>`;
  }
  function chartCard(title, inner) {
    return `<div class="card chart-card"><div class="muted small" style="margin-bottom:6px">${esc(title)}</div>${inner}</div>`;
  }
  function legend(items) {
    return `<div class="legend">` + items.filter(i => i.value > 0).map((i) =>
      `<span><i style="background:${i.color}"></i>${esc(i.label)} ${i.value}</span>`).join("") + `</div>`;
  }

  function toast(msg, kind = "ok") {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.className = "toast " + (kind === "err" ? "err" : "ok");
    setTimeout(() => t.classList.add("hidden"), 3500);
  }

  function modal(title, bodyHtml) {
    document.getElementById("modal-title").textContent = title;
    document.getElementById("modal-body").innerHTML = bodyHtml;
    document.getElementById("modal-overlay").classList.remove("hidden");
  }
  function closeModal() { document.getElementById("modal-overlay").classList.add("hidden"); }
  document.getElementById("modal-close").onclick = closeModal;
  document.getElementById("modal-overlay").onclick = (e) => {
    if (e.target.id === "modal-overlay") closeModal();
  };

  function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
  const loading = () => `<div class="spinner"></div>`;

  // ---------- auth / shell ----------
  function showApp() {
    document.getElementById("login-view").classList.add("hidden");
    document.getElementById("app-view").classList.remove("hidden");
    const u = API.user() || {};
    document.getElementById("user-badge").innerHTML =
      `<b>${esc(u.username)}</b><br><span class="muted small">${esc(u.role)}</span>`;
    document.querySelectorAll(".admin-only").forEach((el) => {
      el.style.display = u.role === "admin" ? "" : "none";
    });
    loadToolSettings();
    buildAssistant();
    navigateFromUrl();
  }
  // Cache of GUI-tunable tool settings (flat {key:value}); used for defaults elsewhere.
  window._tool = {};
  async function loadToolSettings() {
    try {
      const app = await API.get("/api/settings/app");
      const flat = {};
      (app.groups || []).forEach((g) => g.items.forEach((it) => { flat[it.key] = it.value; }));
      window._tool = flat;
      if (_aiBuilt) applyAssistantEnabled();
    } catch (ex) { /* defaults apply until loaded */ }
  }

  // ---------- Offline AI assistant (floating chat widget) ----------
  const AI_HIST_KEY = "pt_ai_history";
  const AI_PLACEHOLDER = "Ask, or say 'scan 10.0.0.5 for open ports'…";
  const AI_WELCOME = "Hi! I'm your offline security assistant. I can **launch scans** for you — "
    + "just say e.g. *'run a port scan on 10.0.0.5'* and I'll walk you through it. I can also "
    + "**explain a CVE** (CVE-2023-2975), **summarise a scan** ('scan #12'), check a **package**, "
    + "or explain a vuln class like **XSS**/**SQLi**. I answer from this platform's local data.";
  let _aiHistory = (() => {
    try { return JSON.parse(localStorage.getItem(AI_HIST_KEY)) || []; } catch (e) { return []; }
  })();
  let _aiBuilt = false;
  let _aiScan = null;  // transient scan-wizard state — NEVER persisted (holds in-memory creds)
  function buildAssistant() {
    if (_aiBuilt) return;
    const root = document.getElementById("ai-root");
    if (!root) return;
    root.innerHTML = `
      <button id="ai-fab" class="ai-fab" title="AI security assistant" onclick="ptAiToggle()">${icon("assistant")}</button>
      <div id="ai-panel" class="ai-panel hidden">
        <div class="ai-head">
          <span class="ai-title">${icon("assistant")} <b>Security Assistant</b> <span id="ai-status" class="ai-status">·</span></span>
          <span class="pill-row">
            <button class="btn btn-sm btn-ghost" onclick="ptAiClear()" title="Clear chat history">Clear</button>
            <button class="btn btn-sm btn-ghost admin-only" onclick="ptAiDisable()" title="Disable the assistant (admins; re-enable in Settings → AI Assistant)">Disable</button>
            <button class="modal-close" onclick="ptAiToggle()" style="font-size:20px">${icon("close")}</button>
          </span>
        </div>
        <div id="ai-msgs" class="ai-msgs"></div>
        <div class="ai-input">
          <input id="ai-text" placeholder="Ask, or say 'scan 10.0.0.5 for open ports'…" onkeydown="if(event.key==='Enter')ptAiSend()">
          <button class="btn btn-primary btn-sm" onclick="ptAiSend()">${icon("send")}</button>
        </div>
      </div>`;
    _aiBuilt = true;
    // Re-apply admin-only visibility to the freshly-built Disable button.
    const isAdmin = (API.user() || {}).role === "admin";
    root.querySelectorAll(".admin-only").forEach((el) => { el.style.display = isAdmin ? "" : "none"; });
    // Restore prior conversation (persisted in localStorage); else show the welcome.
    if (_aiHistory.length) {
      _aiHistory.forEach((m) => aiRenderMsg(m.role, m.content, m.citations));
    } else {
      aiRenderMsg("assistant", AI_WELCOME);
    }
    applyAssistantEnabled();
    refreshAiStatus();
  }
  window.ptAiClear = () => {
    _aiHistory = [];
    try { localStorage.removeItem(AI_HIST_KEY); } catch (e) { /* ignore */ }
    const box = document.getElementById("ai-msgs");
    if (box) box.innerHTML = "";
    aiRenderMsg("assistant", AI_WELCOME);
  };
  // Show/hide the whole widget based on the assistant_enabled setting.
  function applyAssistantEnabled() {
    const root = document.getElementById("ai-root");
    if (!root) return;
    const enabled = (window._tool || {}).assistant_enabled !== false;
    root.style.display = enabled ? "" : "none";
    if (!enabled) document.getElementById("ai-panel")?.classList.add("hidden");
  }
  window.ptAiDisable = async () => {
    if (!confirm("Disable the AI assistant? You can re-enable it in Settings → AI Assistant.")) return;
    try {
      await API.post("/api/assistant/toggle", { enabled: false });
      window._tool = window._tool || {};
      window._tool.assistant_enabled = false;
      applyAssistantEnabled();
      toast("AI assistant disabled");
    } catch (ex) { toast(ex.message, "err"); }
  };
  async function refreshAiStatus() {
    const el = document.getElementById("ai-status");
    if (!el) return;
    try {
      const s = await API.get("/api/assistant/status");
      el.textContent = s.model_online ? "● model online" : "● model offline (DB answers)";
      el.style.color = s.model_online ? "var(--ok)" : "var(--med)";
    } catch { el.textContent = ""; }
  }
  window.ptAiToggle = () => {
    const p = document.getElementById("ai-panel");
    if (!p) return;
    p.classList.toggle("hidden");
    if (!p.classList.contains("hidden")) {
      refreshAiStatus();
      const t = document.getElementById("ai-text");
      if (t) t.focus();
    }
  };
  function aiCitation(c) {
    if (/^CVE-/i.test(c)) return `<a onclick="ptViewCve('${esc(c)}')">${esc(c)}</a>`;
    const m = /^scan#(\d+)$/.exec(c);
    if (m) return `<a onclick="ptAiToggle();ptOpenScan(${m[1]})">scan #${m[1]}</a>`;
    return esc(c);
  }
  // Minimal, safe markdown: escape first, then **bold**, `code`, and newlines.
  function aiFormat(text) {
    let s = esc(text);
    s = s.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/`([^`]+)`/g, "<code>$1</code>");
    return s.replace(/\n/g, "<br>");
  }
  function aiRenderMsg(role, text, citations) {
    const box = document.getElementById("ai-msgs");
    if (!box) return;
    const cites = (citations && citations.length)
      ? `<div class="ai-cites">${citations.map(aiCitation).join(" · ")}</div>` : "";
    box.insertAdjacentHTML("beforeend",
      `<div class="ai-msg ai-${role}"><div class="ai-bubble">${aiFormat(text)}${cites}</div></div>`);
    box.scrollTop = box.scrollHeight;
  }
  function aiPush(role, text, citations) {
    _aiHistory.push({ role, content: text, citations: citations || [] });
    try { localStorage.setItem(AI_HIST_KEY, JSON.stringify(_aiHistory.slice(-50))); } catch (e) { /* quota */ }
    aiRenderMsg(role, text, citations);
  }
  window.ptAiSend = async () => {
    const input = document.getElementById("ai-text");
    const raw = input.value;
    const msg = (raw || "").trim();

    // ---- Scan wizard in progress: this input is a wizard answer (possibly secret) ----
    if (_aiScan) {
      const secret = !!_aiScan.secret;
      if (!msg && !secret) return;
      input.value = "";
      aiRenderMsg("user", secret ? "•••••••• (hidden)" : msg);  // NOT persisted, never sent to model
      aiResetInput();
      aiWizardStep(secret ? raw : msg);
      return;
    }
    if (!msg) return;
    input.value = "";
    aiPush("user", msg);

    // ---- Launch-scan intent → start the in-chat wizard (no model needed) ----
    if (aiLaunchIntent(msg)) { aiStartScanWizard(msg); return; }

    // ---- Normal grounded Q&A ----
    const box = document.getElementById("ai-msgs");
    box.insertAdjacentHTML("beforeend",
      `<div class="ai-msg ai-assistant" id="ai-typing"><div class="ai-bubble"><span class="live-dot"></span>thinking…</div></div>`);
    box.scrollTop = box.scrollHeight;
    try {
      const r = await API.post("/api/assistant/chat", {
        message: msg,
        history: _aiHistory.slice(-6).map((h) => ({ role: h.role, content: h.content })),
      });
      document.getElementById("ai-typing")?.remove();
      aiPush("assistant", r.reply || "(no answer)", r.citations);
    } catch (ex) {
      document.getElementById("ai-typing")?.remove();
      aiPush("assistant", "Error: " + (ex.message || ex));
    }
  };

  // ---------- AI-driven scan launcher (in-chat wizard) ----------
  const AI_SCAN_TYPES = ["discovery", "port", "full", "web", "zap_passive", "zap_active",
                         "credentialed", "cis_benchmark", "custom"];
  function aiResetInput() {
    const i = document.getElementById("ai-text");
    if (i) { i.type = "text"; i.placeholder = AI_PLACEHOLDER; }
  }
  function aiExtractTarget(m) {
    let r = m.match(/https?:\/\/[^\s,]+/i); if (r) return r[0];
    r = m.match(/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?\b/); if (r) return r[0];
    r = m.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i); if (r) return r[0];
    return null;
  }
  function aiParseScanType(m) {
    const s = m.toLowerCase();
    if (AI_SCAN_TYPES.includes(s.trim())) return s.trim();
    if (/\bcis\b|hardening|benchmark/.test(s)) return "cis_benchmark";
    if (/credential|ssh|package audit|authenticated linux|patch audit/.test(s)) return "credentialed";
    if (/zap|owasp|web app/.test(s)) return /active|intrusive/.test(s) ? "zap_active" : "zap_passive";
    if (/\bweb\b|url|http/.test(s)) return "web";
    if (/discovery|ping|sweep|alive|host disc/.test(s)) return "discovery";
    if (/\bport\b/.test(s)) return "port";
    if (/full|server va|version detect|service detect|\bvuln\b|\bcve\b/.test(s)) return "full";
    if (/custom|nmap flag/.test(s)) return "custom";
    return null;
  }
  function aiLaunchIntent(m) {
    const s = m.toLowerCase();
    if (/\b(summar|result|explain|status|finding|report|what|which|how|list)\b/.test(s)) return false;
    if (/\b(start|launch|run|begin|initiate|perform|kick off|new)\b[\s\S]*\bscan\b/.test(s)) return true;
    return /\bscan\b/.test(s) && !!aiExtractTarget(m);
  }
  function aiStartScanWizard(msg) {
    const role = (API.user() || {}).role;
    if (role === "viewer") {
      aiPush("assistant", "⚠ You're signed in as a **viewer** and can't launch scans. Ask an operator/admin.");
      return;
    }
    _aiScan = { target: aiExtractTarget(msg) || "", scan_type: aiParseScanType(msg) || "", ssh_port: 22 };
    aiWizardAdvance();
  }
  function aiWizardAsk(text) {
    aiRenderMsg("assistant", text);
    const input = document.getElementById("ai-text");
    if (input) {
      input.type = (_aiScan && _aiScan.secret) ? "password" : "text";
      input.placeholder = (_aiScan && _aiScan.secret) ? "hidden — never stored or sent to the model" : "Type your answer…";
      input.focus();
    }
  }
  function aiWizardSummary() {
    const s = _aiScan;
    const L = ["**Ready to launch:**", `• Target: \`${s.target}\``, `• Scan type: **${s.scan_type}**`];
    if (s.scan_type === "custom") L.push(`• nmap flags: \`${s.custom_flags}\``);
    if (s.ssh_username) L.push(`• SSH: ${s.ssh_username}@${s.target}:${s.ssh_port} (${s.authMethod === "key" ? "private key" : "password"})`);
    if (s.cis_level) L.push(`• CIS profile: ${s.cis_level}`);
    return L.join("\n");
  }
  function aiWizardAdvance() {
    const s = _aiScan;
    s.secret = false;
    if (!s.target) { s.step = "target"; return aiWizardAsk("🎯 What's the **target**? (IP, hostname, CIDR, or URL)"); }
    if (!s.scan_type) { s.step = "type"; return aiWizardAsk("🔍 What **type of scan**?\ndiscovery · port · full (server VA) · web · zap_passive · zap_active · credentialed · cis_benchmark · custom"); }
    if (s.scan_type === "custom" && !s.custom_flags) { s.step = "custom_flags"; return aiWizardAsk("⚙️ Enter the **custom nmap flags** (e.g. `-sT -sV -p 1-1000`)."); }
    if (s.scan_type === "credentialed" || s.scan_type === "cis_benchmark") {
      if (!s.ssh_username) { s.step = "ssh_user"; return aiWizardAsk("🔐 **SSH username**?"); }
      if (!s.portAsked) { s.step = "ssh_port"; s.portAsked = true; return aiWizardAsk("🔌 **SSH port**? (type 22 for the default)"); }
      if (!s.authMethod) { s.step = "auth_method"; return aiWizardAsk("🔑 Authenticate with a **password** or a **key**? (type `password` or `key`)"); }
      if (s.authMethod === "password" && !s.ssh_password) { s.step = "ssh_password"; s.secret = true; return aiWizardAsk("🔒 Enter the **SSH password**. (hidden — used in-memory only, never stored)"); }
      if (s.authMethod === "key" && !s.ssh_key) { s.step = "ssh_key"; s.secret = true; return aiWizardAsk("🔒 Paste the **private key** (PEM). (hidden — used in-memory only, never stored)"); }
      if (s.scan_type === "cis_benchmark" && !s.cisAsked) { s.step = "cis_level"; s.cisAsked = true; return aiWizardAsk("🛡 CIS **level**?  1) L1 Server (default)  2) L2 Server  3) L1 Workstation  4) L2 Workstation — type 1-4."); }
    }
    s.step = "confirm";
    aiWizardAsk(aiWizardSummary() + "\n\n**Launch this scan?** (yes / no)");
  }
  function aiWizardStep(value) {
    const s = _aiScan;
    const v = (value || "").trim();
    if (!s.secret && /^(cancel|stop|quit|abort|nevermind)$/i.test(v)) {
      aiRenderMsg("assistant", "Okay — cancelled, no scan started."); _aiScan = null; aiResetInput(); return;
    }
    switch (s.step) {
      case "target": s.target = aiExtractTarget(v) || v; break;
      case "type": {
        const t = aiParseScanType(v);
        if (!t) return aiWizardAsk("I didn't recognise that. Try: discovery, port, full, web, zap_passive, zap_active, credentialed, cis_benchmark, custom.");
        s.scan_type = t; break;
      }
      case "custom_flags": if (!v) return aiWizardAsk("Please enter nmap flags."); s.custom_flags = v; break;
      case "ssh_user": if (!v) return aiWizardAsk("Username can't be empty."); s.ssh_username = v; break;
      case "ssh_port": s.ssh_port = parseInt(v, 10) || 22; break;
      case "auth_method": {
        const a = v.toLowerCase();
        if (/^pass|pwd/.test(a)) s.authMethod = "password";
        else if (/key|pem/.test(a)) s.authMethod = "key";
        else return aiWizardAsk("Type `password` or `key`.");
        break;
      }
      case "ssh_password": if (!value) return aiWizardAsk("Password can't be empty."); s.ssh_password = value; break;
      case "ssh_key": if (!value) return aiWizardAsk("Key can't be empty."); s.ssh_key = value; break;
      case "cis_level": {
        s.cis_level = ({ "1": "_cis_server_l1", "2": "_cis", "3": "_cis_workstation_l1", "4": "_cis_workstation_l2" })[v.trim()] || "_cis_server_l1";
        break;
      }
      case "confirm": {
        const a = v.toLowerCase();
        if (/^y/.test(a)) return aiWizardLaunch();
        if (/^n/.test(a)) { aiRenderMsg("assistant", "Okay — cancelled, no scan started."); _aiScan = null; return; }
        return aiWizardAsk("Please answer **yes** or **no**.");
      }
    }
    aiWizardAdvance();
  }
  async function aiWizardLaunch() {
    const s = _aiScan;
    aiRenderMsg("assistant", "⏳ Launching… resolving target.");
    let t;
    try {
      const targets = await API.get("/api/targets");
      t = targets.find((x) => (x.address || "").toLowerCase() === s.target.toLowerCase());
      if (!t) t = await API.post("/api/targets", { name: s.target, address: s.target, tags: "ai", description: "Created by AI assistant" });
    } catch (ex) { aiPush("assistant", "❌ Couldn't resolve/create the target: " + ex.message); _aiScan = null; aiResetInput(); return; }
    const body = { target_id: t.id, scan_type: s.scan_type };
    if (s.scan_type === "custom") body.custom_flags = s.custom_flags;
    if (s.scan_type === "credentialed" || s.scan_type === "cis_benchmark") {
      body.ssh_username = s.ssh_username; body.ssh_port = s.ssh_port || 22;
      if (s.ssh_password) body.ssh_password = s.ssh_password;
      if (s.ssh_key) body.ssh_key = s.ssh_key;
      if (s.scan_type === "cis_benchmark") body.cis_profile = s.cis_level || "_cis_server_l1";
    }
    const target = s.target;
    _aiScan = null;  // drop in-memory credentials immediately after building the request
    aiResetInput();
    let scan;
    try { scan = await API.post("/api/scans", body); }
    catch (ex) { aiPush("assistant", "❌ Scan rejected: " + (ex.message || ex)); return; }
    aiPush("assistant", `✅ **Scan #${scan.id}** (${body.scan_type}) started on \`${target}\`. I'll report back when it finishes — you can keep chatting meanwhile.`, [`scan#${scan.id}`]);
    aiWatchScan(scan.id, target);
  }
  function aiWatchScan(id) {
    let tries = 0;
    const poll = async () => {
      tries++;
      let sc;
      try { sc = await API.get(`/api/scans/${id}`); }
      catch (e) { if (tries < 120) setTimeout(poll, 6000); return; }
      if (["completed", "failed", "cancelled"].includes(sc.status)) return aiReportScan(id, sc);
      if (tries >= 200) { aiPush("assistant", `⏱ Scan #${id} is still running. Ask me "summarise scan #${id}" later.`, [`scan#${id}`]); return; }
      setTimeout(poll, 6000);
    };
    setTimeout(poll, 6000);
  }
  async function aiReportScan(id, sc) {
    if (sc.status !== "completed") {
      aiPush("assistant", `Scan #${id} **${sc.status}**.` + (sc.error ? ` ${sc.error}` : ""), [`scan#${id}`]);
      return;
    }
    try {
      const r = await API.post("/api/assistant/chat", { message: `Summarise scan #${id}` });
      aiPush("assistant", `✅ **Scan #${id} complete.**\n\n` + (r.reply || ""),
        (r.citations && r.citations.length) ? r.citations : [`scan#${id}`]);
    } catch (ex) {
      aiPush("assistant", `✅ Scan #${id} complete (${sc.result_count || 0} results). Open it for full details.`, [`scan#${id}`]);
    }
  }
  function showLogin() {
    stopPolling();
    document.getElementById("app-view").classList.add("hidden");
    document.getElementById("login-view").classList.remove("hidden");
  }

  document.getElementById("login-form").onsubmit = async (e) => {
    e.preventDefault();
    const err = document.getElementById("login-error");
    err.textContent = "";
    try {
      await API.login(
        document.getElementById("login-username").value.trim(),
        document.getElementById("login-password").value
      );
      showApp();
    } catch (ex) { err.textContent = ex.message; }
  };
  document.getElementById("logout-btn").onclick = () => { API.clear(); showLogin(); };
  window.addEventListener("pt-unauthorized", showLogin);

  // ---------- theme ----------
  function applyTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem("pt_theme", t);
    const btn = document.getElementById("theme-btn");
    if (btn) btn.textContent = t === "light" ? "🌙 Dark mode" : "☀️ Light mode";
  }
  document.getElementById("theme-btn").onclick = () => {
    const cur = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
    applyTheme(cur === "light" ? "dark" : "light");
  };
  applyTheme(localStorage.getItem("pt_theme") || "dark");
  applyNavIcons();

  // ---------- routing (path-based, reflected in the browser URL) ----------
  const ROUTES = { dashboard: renderDashboard, targets: renderTargets, scans: renderScans,
                   schedules: renderSchedules, cves: renderCves, reports: renderReports,
                   settings: renderSettings, users: renderUsers, about: renderAbout };

  document.getElementById("nav").addEventListener("click", (e) => {
    const item = e.target.closest(".nav-item");
    if (!item) return;
    route(item.dataset.route);
  });

  function setActiveNav(r) {
    document.querySelectorAll(".nav-item").forEach((el) =>
      el.classList.toggle("active", el.dataset.route === r));
  }

  function route(r, arg, push = true) {
    stopPolling();
    setActiveNav(r);
    if (push) {
      const path = r === "dashboard" ? "/" : "/" + r;
      if (window.location.pathname !== path) history.pushState({}, "", path);
    }
    (ROUTES[r] || renderDashboard)(arg);
  }
  window.ptRoute = route; // for inline handlers

  // Render the view that matches the current URL path (deep-link / back-forward support).
  function navigateFromUrl() {
    const seg = window.location.pathname.replace(/^\/+|\/+$/g, "").split("/");
    if (seg[0] === "scans" && seg[1]) { stopPolling(); setActiveNav("scans"); renderScanDetail(seg[1]); return; }
    const r = ROUTES[seg[0]] ? seg[0] : "dashboard";
    route(r, undefined, false);
  }
  window.addEventListener("popstate", () => { if (API.token()) navigateFromUrl(); });

  // ---------- Dashboard ----------
  async function renderDashboard() {
    view.innerHTML = pageHead("dashboard", "Dashboard") + loading();
    try {
      const s = await API.get("/api/dashboard/stats");
      const sev = s.severity_breakdown || {};
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const segs = order.map((k) => ({ label: k, value: sev[k] || 0, color: SEV_COLOR[k] }));
      const sevTotal = segs.reduce((a, x) => a + x.value, 0);

      // Stat cards — KEV and Critical/High get accent treatment.
      const cardDefs = [
        ["Targets", s.targets, "", "targets"], ["Scans", s.scans, "", "scans"],
        ["Hosts", s.hosts, "", "server"], ["CVEs in DB", (s.cves || 0).toLocaleString(), "", "cves"],
        ["Open Crit/High", s.crit_high_open ?? 0, "crit", "alert"],
        ["Exploited (KEV)", s.kev_findings ?? 0, "kev", "flame"],
      ];
      const cards = cardDefs.map(([l, n, cls, ic]) =>
        `<div class="card stat-card ${cls === "kev" ? "stat-kev" : cls === "crit" ? "stat-crit" : ""}">
          <div class="stat-top"><div class="stat-num">${n}</div><div class="stat-ic">${icon(ic)}</div></div>
          <div class="stat-label">${l}</div></div>`).join("");

      // Scan-status breakdown bars.
      const ss = s.scan_status || {};
      const ssColor = { completed: "var(--ok)", running: "var(--med)", queued: "var(--low)",
                        failed: "var(--high)", cancelled: "var(--muted)" };
      const ssItems = Object.keys(ss).sort((a, b) => ss[b] - ss[a])
        .map((k) => ({ label: k, value: ss[k], color: ssColor[k] || "var(--info)" }));

      // Top priorities (KEV / high-risk findings).
      const topRows = (s.top_risk || []).map((f) => `
        <tr onclick="ptViewCve('${esc(f.cve_id)}')" style="cursor:pointer">
          <td class="mono nowrap">${esc(f.cve_id)}${f.kev ? ' <span class="sev-badge sev-critical" title="Actively exploited (CISA KEV)">KEV</span>' : ""}</td>
          <td>${esc(f.package || "—")}</td>
          <td>${sevBadge(f.severity)}</td>
          <td class="nowrap small">${f.cvss ?? "—"}</td>
          <td class="nowrap small">${f.epss != null ? (f.epss * 100).toFixed(1) + "%" : "—"}</td>
        </tr>`).join("") || `<tr><td colspan="5" class="empty">No findings yet</td></tr>`;

      const recent = (s.recent_scans || []).map((sc) => `
        <tr onclick="ptOpenScan(${sc.id})" style="cursor:pointer">
          <td>#${sc.id}</td><td>${esc(sc.scan_type)}</td>
          <td>${statusBadge(sc.status)}</td><td>${sc.finding_count}</td>
          <td class="small">${fmtDate(sc.created_at)}</td></tr>`).join("") ||
        `<tr><td colspan="5" class="empty">No scans yet</td></tr>`;

      view.innerHTML = pageHead("dashboard", "Dashboard") + `
        <div class="grid stat-grid">${cards}</div>
        <div class="chart-row" style="margin-top:18px">
          ${chartCard("Findings by severity",
            sevTotal ? `<div class="donut-wrap">${svgDonut(segs, String(sevTotal), "findings")}${legend(segs)}</div>`
                     : `<p class="muted small">No findings yet — run a scan to populate.</p>`)}
          ${chartCard("Scans by status",
            ssItems.length ? svgBars(ssItems) : `<p class="muted small">No scans yet.</p>`)}
        </div>
        <h3 class="section-title">🎯 Top priorities (exploited / high-risk)</h3>
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:24%"><col style="width:30%"><col style="width:16%"><col style="width:14%"><col style="width:16%"></colgroup>
          <thead><tr><th>CVE</th><th>Package / service</th><th>Severity</th><th>CVSS</th><th>EPSS</th></tr></thead>
          <tbody>${topRows}</tbody></table></div>
        <h3 class="section-title">Recent scans</h3>
        <div class="table-wrap"><table>
          <thead><tr><th>Scan</th><th>Type</th><th>Status</th><th>Findings</th><th>Created</th></tr></thead>
          <tbody>${recent}</tbody></table></div>`;
    } catch (ex) { view.innerHTML = errBox(ex); }
  }

  // ---------- Targets ----------
  async function renderTargets() {
    view.innerHTML = pageHead("targets", "Targets",
      `<button class="btn btn-primary" onclick="ptNewTarget()">+ Add target</button>`) + loading();
    try {
      const targets = await API.get("/api/targets");
      const rows = targets.map((t) => `
        <tr>
          <td><b>${esc(t.name)}</b></td>
          <td class="mono">${esc(t.address)}</td>
          <td>${esc(t.tags)}</td>
          <td>${esc(t.description)}</td>
          <td class="pill-row">
            <button class="btn btn-sm btn-primary" onclick="ptScanTarget(${t.id},'${esc(t.name)}','${esc(t.address)}')">Scan</button>
            <button class="btn btn-sm" onclick='ptEditTarget(${JSON.stringify(t)})'>Edit</button>
            <button class="btn btn-sm btn-danger" onclick="ptDelTarget(${t.id})">Delete</button>
          </td></tr>`).join("") ||
        `<tr><td colspan="5" class="empty">No targets. Add one to begin.</td></tr>`;
      view.innerHTML = pageHead("targets", "Targets",
        `<button class="btn btn-primary" onclick="ptNewTarget()">+ Add target</button>`) + `
        <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Address / URL</th><th>Tags</th><th>Description</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) { view.innerHTML = errBox(ex); }
  }

  function targetForm(t = {}) {
    return `
      <div class="form-row"><label>Name</label><input id="t-name" value="${esc(t.name || "")}" placeholder="e.g. Web server prod"></div>
      <div class="form-row"><label>Address(es) / URL / CIDR</label>
        <textarea id="t-address" rows="2" placeholder="One or more, separated by space, comma or newline — e.g. 10.0.0.5, 10.0.0.6  10.0.0.0/24  or  https://app.local">${esc(t.address || "")}</textarea>
        <span class="muted small">Multiple IPs/hosts allowed in a single target (scanned together).</span>
      </div>
      <div class="form-row"><label>Tags (comma separated)</label><input id="t-tags" value="${esc(t.tags || "")}" placeholder="prod, dmz"></div>
      <div class="form-row"><label>Description</label><textarea id="t-desc" rows="2">${esc(t.description || "")}</textarea></div>
      <button class="btn btn-primary btn-block" onclick="ptSaveTarget(${t.id || 0})">Save</button>`;
  }
  window.ptNewTarget = () => modal("Add target", targetForm());
  window.ptEditTarget = (t) => modal("Edit target", targetForm(t));
  window.ptSaveTarget = async (id) => {
    const payload = {
      name: document.getElementById("t-name").value.trim(),
      address: document.getElementById("t-address").value.trim(),
      tags: document.getElementById("t-tags").value.trim(),
      description: document.getElementById("t-desc").value.trim(),
    };
    if (!payload.name || !payload.address) { toast("Name and address are required", "err"); return; }
    try {
      if (id) await API.put(`/api/targets/${id}`, payload);
      else await API.post("/api/targets", payload);
      closeModal(); toast("Target saved"); renderTargets();
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptDelTarget = async (id) => {
    if (!confirm("Delete this target and all its scans?")) return;
    try { await API.del(`/api/targets/${id}`); toast("Deleted"); renderTargets(); }
    catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Launch scan ----------
  // Re-run a scan: reopen the launch dialog for the same target, pre-selected to the
  // same scan type. Credentials aren't stored, so SSH/ZAP scans re-prompt for them.
  window.ptRescan = async (targetId, scanType) => {
    try {
      const t = await API.get(`/api/targets/${targetId}`);
      ptScanTarget(t.id, t.name, t.address);
      const sel = document.getElementById("s-type");
      if (sel) {
        // Only preselect if this scan type is offered in the dialog.
        if ([...sel.options].some((o) => o.value === scanType)) sel.value = scanType;
        ptToggleScanFields();
      }
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptScanTarget = (id, name, address) => {
    modal(`Launch scan — ${esc(name)}`, `
      <p class="muted small">Target: <code>${esc(address)}</code></p>
      <div class="form-row"><label>Scan type</label>
        <select id="s-type" onchange="ptToggleScanFields()">
          <option value="full">Server vulnerability assessment (nmap -sV + CVE)</option>
          <option value="credentialed">Credentialed Linux assessment (SSH package audit)</option>
          <option value="cis_benchmark">CIS benchmark / hardening audit (OpenSCAP, authenticated)</option>
          <option value="discovery">Host discovery (ping sweep)</option>
          <option value="port">Port scan (open ports only)</option>
          <option value="web">Web / URL test — built-in (passive, non-destructive)</option>
          <option value="zap_passive">Web app scan — OWASP ZAP (spider + passive)</option>
          <option value="zap_active">Web app scan — OWASP ZAP (full active · intrusive)</option>
          <option value="custom">Custom nmap flags</option>
        </select></div>
        <div class="form-row hidden" id="s-zap-warn"><span class="small" style="color:var(--med)">⚠ Active scanning sends real attack payloads (XSS/SQLi/etc.). Only run against systems you are explicitly authorized to actively test.</span></div>
      <div class="form-row hidden" id="s-custom-row"><label>Custom nmap flags</label>
        <input id="s-custom" placeholder="-sT -sV -p 1-1000 --script vuln"></div>
      <div id="s-cred-rows" class="hidden">
        <div class="card" style="background:var(--bg-2);margin-bottom:6px">
          <p class="small muted" id="s-cis-note" style="margin-bottom:10px;display:none">🛡 Runs the official <b>CIS benchmark via OpenSCAP</b> (auto-installed on the target if missing); otherwise falls back to built-in hardening checks. Use an account with sufficient privilege (sudo/root) for full coverage.</p>
          <div class="form-row" id="s-cis-level-row" style="display:none"><label>CIS profile / level</label>
            <select id="s-cis-level">
              <option value="_cis_server_l1">Level 1 — Server (recommended)</option>
              <option value="_cis">Level 2 — Server</option>
              <option value="_cis_workstation_l1">Level 1 — Workstation</option>
              <option value="_cis_workstation_l2">Level 2 — Workstation</option>
            </select></div>
          <p class="small muted" style="margin-bottom:10px">🔐 Credentials are used in-memory for this scan only and are <b>never stored</b>. The target address is used as the SSH host.</p>
          <div class="form-row"><label>SSH username</label><input id="s-user" placeholder="e.g. ec2-user" autocomplete="off"></div>
          <div class="form-row"><label>SSH port</label><input id="s-port" type="number" value="22"></div>
          <div class="form-row"><label>Password</label><input id="s-pass" type="password" autocomplete="new-password" placeholder="leave blank if using a key"></div>
          <div class="form-row"><label>Private key (optional, PEM)</label><textarea id="s-key" rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY----- ..."></textarea></div>
          <div class="form-row"><label>Key passphrase (optional)</label><input id="s-keypass" type="password" autocomplete="new-password"></div>
        </div>
      </div>
      <div id="s-zap-rows" class="hidden">
        <div class="card" style="background:var(--bg-2);margin-bottom:6px">
          <div class="form-row"><label class="muted small"><input type="checkbox" id="s-zap-ajax" style="width:auto"> <b>Use AJAX spider</b> (browser-driven) — required to crawl JavaScript / SPA apps (Angular, React, Vue) whose routes the normal spider can't see</label></div>
          <p class="small muted" style="margin-bottom:10px">🔐 <b>Authenticated scan (optional)</b> — supply a login so ZAP crawls and tests pages behind authentication for a much deeper scan. Credentials are used in-memory only and are <b>never stored</b>. Leave the username blank for an anonymous scan.</p>
          <div class="form-row"><label>Auth type</label>
            <select id="s-zap-authtype" onchange="ptZapAuthHint()">
              <option value="form">Form-based login (HTML login form)</option>
              <option value="json">JSON login (SPA / API endpoint)</option>
              <option value="http">HTTP Basic / NTLM</option>
            </select></div>
          <div class="form-row"><label>Login username</label><input id="s-zap-user" placeholder="e.g. testuser" autocomplete="off"></div>
          <div class="form-row"><label>Login password</label><input id="s-zap-pass" type="password" autocomplete="new-password"></div>
          <div class="form-row"><label>Login URL</label><input id="s-zap-loginurl" placeholder="https://site/login (where credentials are POSTed)"></div>
          <p class="small muted" id="s-zap-loginhint" style="margin:-4px 0 8px;display:none">⚠ For SPAs this is the <b>login API endpoint</b> (e.g. <code>/api/auth/login</code>, <code>/rest/user/login</code>) that accepts the POST — <b>not</b> the sign-in page route.</p>
          <div class="form-row"><label>Username field name</label><input id="s-zap-userfield" value="username"></div>
          <div class="form-row"><label>Password field name</label><input id="s-zap-passfield" value="password"></div>
          <div class="form-row"><label>Session handling</label>
            <select id="s-zap-session" onchange="ptZapSessionFields()">
              <option value="cookie">Cookie session (traditional server-rendered apps)</option>
              <option value="header">Bearer token in header (SPA / API — token from login response)</option>
            </select></div>
          <div id="s-zap-token-rows" style="display:none">
            <div class="form-row"><label>Token field (in login JSON)</label><input id="s-zap-tokenfield" value="token" placeholder="e.g. token, access_token, data.token, authentication.token"></div>
            <div class="form-row"><label>Custom session header(s) (optional)</label><input id="s-zap-sessionhdr" placeholder="Authorization: Bearer {%json:token%}  (overrides token field)"></div>
          </div>
          <div class="form-row"><label>Extra login params (optional)</label><input id="s-zap-extra" placeholder="csrf_token=abc&submit=Login"></div>
          <div class="form-row"><label>Logged-in indicator regex (optional)</label><input id="s-zap-inregex" placeholder="e.g. \\bLogout\\b — helps ZAP re-login on session expiry"></div>
          <div class="form-row"><label>Logged-out indicator regex (optional)</label><input id="s-zap-outregex" placeholder="e.g. Login|Sign in"></div>
        </div>
      </div>
      <button class="btn btn-primary btn-block" onclick="ptStartScan(${id})">Start scan</button>
      <p class="muted small" style="margin-top:10px">For web tests, set the target address to a URL (http/https). Only scan systems you are authorized to test.</p>`);
    // Pre-select the configured default scan type (Settings → Scanning).
    const def = (window._tool || {}).scan_default_profile;
    const sel = document.getElementById("s-type");
    if (sel && def && [...sel.options].some((o) => o.value === def)) {
      sel.value = def;
      ptToggleScanFields();
    }
  };
  window.ptToggleScanFields = () => {
    const v = document.getElementById("s-type").value;
    const sshScan = v === "credentialed" || v === "cis_benchmark";
    document.getElementById("s-custom-row").classList.toggle("hidden", v !== "custom");
    document.getElementById("s-cred-rows").classList.toggle("hidden", !sshScan);
    document.getElementById("s-cis-note").style.display = v === "cis_benchmark" ? "" : "none";
    document.getElementById("s-cis-level-row").style.display = v === "cis_benchmark" ? "" : "none";
    document.getElementById("s-zap-warn").classList.toggle("hidden", v !== "zap_active");
    document.getElementById("s-zap-rows").classList.toggle(
      "hidden", v !== "zap_passive" && v !== "zap_active");
  };
  window.ptZapSessionFields = () => {
    const header = document.getElementById("s-zap-session").value === "header";
    document.getElementById("s-zap-token-rows").style.display = header ? "" : "none";
  };
  window.ptZapAuthHint = () => {
    // Nudge towards header/token session + the API endpoint when JSON auth is chosen.
    const isJson = document.getElementById("s-zap-authtype").value === "json";
    document.getElementById("s-zap-loginhint").style.display = isJson ? "" : "none";
    if (isJson && document.getElementById("s-zap-session").value === "cookie") {
      document.getElementById("s-zap-session").value = "header";
      ptZapSessionFields();
    }
  };
  window.ptStartScan = async (target_id) => {
    const scan_type = document.getElementById("s-type").value;
    const body = { target_id, scan_type };
    if (scan_type === "custom") body.custom_flags = document.getElementById("s-custom").value.trim();
    if (scan_type === "credentialed" || scan_type === "cis_benchmark") {
      body.ssh_username = document.getElementById("s-user").value.trim();
      body.ssh_password = document.getElementById("s-pass").value || null;
      body.ssh_key = document.getElementById("s-key").value.trim() || null;
      body.ssh_key_passphrase = document.getElementById("s-keypass").value || null;
      body.ssh_port = parseInt(document.getElementById("s-port").value, 10) || 22;
      if (!body.ssh_username || (!body.ssh_password && !body.ssh_key)) {
        toast("Username and a password or private key are required", "err"); return;
      }
      if (scan_type === "cis_benchmark") body.cis_profile = document.getElementById("s-cis-level").value;
    }
    if (scan_type === "zap_passive" || scan_type === "zap_active") {
      body.zap_ajax_spider = document.getElementById("s-zap-ajax").checked;
      const zu = document.getElementById("s-zap-user").value.trim();
      if (zu) {  // authenticated scan requested
        const at = document.getElementById("s-zap-authtype").value;
        const loginUrl = document.getElementById("s-zap-loginurl").value.trim();
        if (at !== "http" && !loginUrl) {
          toast("Form/JSON authenticated scans require a login URL", "err"); return;
        }
        body.zap_username = zu;
        body.zap_password = document.getElementById("s-zap-pass").value || null;
        body.zap_auth_type = at;
        body.zap_login_url = loginUrl || null;
        body.zap_username_field = document.getElementById("s-zap-userfield").value.trim() || "username";
        body.zap_password_field = document.getElementById("s-zap-passfield").value.trim() || "password";
        body.zap_extra_post_data = document.getElementById("s-zap-extra").value.trim() || null;
        body.zap_logged_in_regex = document.getElementById("s-zap-inregex").value.trim() || null;
        body.zap_logged_out_regex = document.getElementById("s-zap-outregex").value.trim() || null;
        body.zap_session = document.getElementById("s-zap-session").value;
        body.zap_token_field = document.getElementById("s-zap-tokenfield").value.trim() || "token";
        body.zap_session_headers = document.getElementById("s-zap-sessionhdr").value.trim() || null;
      }
    }
    try {
      const scan = await API.post("/api/scans", body);
      closeModal(); toast(`Scan #${scan.id} started`);
      route("scans");
    } catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Scans ----------
  async function renderScans() {
    // Build the static shell ONCE; polling only updates the tbody so the page
    // doesn't flicker / lose scroll position on each refresh.
    view.innerHTML = pageHead("scans", "Scans",
      `<span class="muted small">⟳ Auto-refreshing</span>`) + `
      <div class="table-wrap"><table>
      <thead><tr><th>Scan</th><th>Target</th><th>Type</th><th>Status</th><th>Results</th><th>By</th><th>Created</th><th></th></tr></thead>
      <tbody id="scans-tbody"><tr><td colspan="8">${loading()}</td></tr></tbody></table></div>`;
    await refreshScans();
    pollTimer = setInterval(refreshScans, 5000);
  }
  async function refreshScans() {
    const tbody = document.getElementById("scans-tbody");
    if (!tbody) { stopPolling(); return; }  // navigated away
    try {
      const [scans, targets] = await Promise.all([API.get("/api/scans"), API.get("/api/targets")]);
      const tmap = {}; targets.forEach((t) => (tmap[t.id] = t));
      const rows = scans.map((s) => {
        const t = tmap[s.target_id] || {};
        const prog = s.status === "running" ? ` <span class="muted small">${s.progress}%</span>` : "";
        return `<tr onclick="ptOpenScan(${s.id})" style="cursor:pointer">
          <td>#${s.id}</td>
          <td><b>${esc(t.name || "?")}</b><br><span class="muted small mono">${esc(t.address || "")}</span></td>
          <td>${esc(s.scan_type)}</td>
          <td>${statusBadge(s.status)}${prog}</td>
          <td>${s.status === "completed" || (s.result_count || 0) > 0
                ? `<b>${s.result_count || 0}</b>` : '<span class="muted">—</span>'}</td>
          <td>${esc(s.created_by)}</td>
          <td>${fmtDate(s.created_at)}</td>
          <td onclick="event.stopPropagation()" class="pill-row">
            <button class="btn btn-sm" onclick="ptOpenScan(${s.id})">View</button>
            ${(s.status === "running" || s.status === "queued") ? `<button class="btn btn-sm" onclick="ptCancelScan(${s.id})">⏹ Stop</button>` : ""}
            <button class="btn btn-sm btn-danger" onclick="ptDelScan(${s.id})">Del</button>
          </td></tr>`;
      }).join("") || `<tr><td colspan="8" class="empty">No scans yet. Launch one from Targets.</td></tr>`;
      tbody.innerHTML = rows;
    } catch (ex) { stopPolling(); tbody.innerHTML = `<tr><td colspan="8">${errBox(ex)}</td></tr>`; }
  }
  window.ptDelScan = async (id) => {
    if (!confirm("Delete scan #" + id + "?")) return;
    try { await API.del(`/api/scans/${id}`); toast("Deleted"); refreshScans(); }
    catch (ex) { toast(ex.message, "err"); }
  };
  window.ptCancelScan = async (id) => {
    if (!confirm("Stop scan #" + id + "? It will halt at the next safe point.")) return;
    try {
      await API.post(`/api/scans/${id}/cancel`);
      toast("Stop requested — the scan will halt shortly");
      if (typeof refreshScans === "function") refreshScans();
    } catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Schedules ----------
  const SCHED_TYPES = [
    ["full", "Server VA (nmap -sV + CVE)"], ["discovery", "Host discovery"],
    ["port", "Port scan"], ["web", "Web / URL (built-in)"],
    ["zap_passive", "ZAP passive"], ["zap_active", "ZAP active"], ["custom", "Custom nmap"],
  ];
  async function renderSchedules() {
    view.innerHTML = pageHead("schedules", "Scheduled scans",
      `<button class="btn btn-primary" onclick="ptNewSchedule()">+ New schedule</button>`) + `
      <p class="muted small">Recurring scans run automatically. Credentialed/CIS scans aren't schedulable (they need in-memory credentials that are never stored).</p>
      <div id="sched-box">${loading()}</div>`;
    try {
      const [schs, targets] = await Promise.all([API.get("/api/schedules"), API.get("/api/targets")]);
      const tmap = {}; targets.forEach(t => tmap[t.id] = t);
      window._targets = targets;
      const rows = schs.map(s => {
        const t = tmap[s.target_id] || {};
        return `<tr>
          <td><b>${esc(t.name || "?")}</b><br><span class="muted small mono">${esc(t.address || "")}</span></td>
          <td>${esc(s.scan_type)}</td>
          <td>every ${s.interval_hours}h</td>
          <td>${s.enabled ? '<span class="status-badge status-completed">on</span>' : '<span class="status-badge">off</span>'}</td>
          <td class="small">${fmtDate(s.last_run)}</td>
          <td class="small">${fmtDate(s.next_run)}</td>
          <td onclick="event.stopPropagation()" class="pill-row">
            <button class="btn btn-sm" onclick="ptRunSchedule(${s.id})">Run now</button>
            <button class="btn btn-sm" onclick="ptToggleSchedule(${s.id}, ${s.enabled ? "false" : "true"})">${s.enabled ? "Disable" : "Enable"}</button>
            <button class="btn btn-sm btn-danger" onclick="ptDelSchedule(${s.id})">Del</button>
          </td></tr>`;
      }).join("") || `<tr><td colspan="7" class="empty">No schedules. Create one to run scans automatically.</td></tr>`;
      document.getElementById("sched-box").innerHTML = `<div class="table-wrap"><table>
        <thead><tr><th>Target</th><th>Type</th><th>Interval</th><th>Enabled</th><th>Last run</th><th>Next run</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) { document.getElementById("sched-box").innerHTML = errBox(ex); }
  }
  window.ptNewSchedule = () => {
    const targets = window._targets || [];
    if (!targets.length) { toast("Create a target first", "err"); return; }
    modal("New scheduled scan", `
      <div class="form-row"><label>Target</label><select id="sc-target">
        ${targets.map(t => `<option value="${t.id}">${esc(t.name)} (${esc(t.address)})</option>`).join("")}</select></div>
      <div class="form-row"><label>Scan type</label><select id="sc-type" onchange="ptSchedCustomToggle()">
        ${SCHED_TYPES.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join("")}</select></div>
      <div class="form-row hidden" id="sc-custom-row"><label>Custom nmap flags</label><input id="sc-custom" placeholder="-sT -sV -p 1-1000"></div>
      <div class="form-row"><label>Run every (hours)</label><input id="sc-interval" type="number" value="24" min="1"></div>
      <button class="btn btn-primary btn-block" onclick="ptSaveSchedule()">Create schedule</button>`);
  };
  window.ptSchedCustomToggle = () => {
    document.getElementById("sc-custom-row").classList.toggle("hidden",
      document.getElementById("sc-type").value !== "custom");
  };
  window.ptSaveSchedule = async () => {
    const body = {
      target_id: parseInt(document.getElementById("sc-target").value, 10),
      scan_type: document.getElementById("sc-type").value,
      custom_flags: (document.getElementById("sc-custom") || {}).value || "",
      interval_hours: parseInt(document.getElementById("sc-interval").value, 10) || 24,
      enabled: true,
    };
    try { await API.post("/api/schedules", body); closeModal(); toast("Schedule created"); renderSchedules(); }
    catch (ex) { toast(ex.message, "err"); }
  };
  window.ptRunSchedule = async (id) => {
    try { const r = await API.post(`/api/schedules/${id}/run`); toast(r.message); }
    catch (ex) { toast(ex.message, "err"); }
  };
  window.ptToggleSchedule = async (id, enable) => {
    try {
      const schs = await API.get("/api/schedules");
      const s = schs.find(x => x.id === id); if (!s) return;
      await API.put(`/api/schedules/${id}`, { target_id: s.target_id, scan_type: s.scan_type,
        custom_flags: s.custom_flags, interval_hours: s.interval_hours, enabled: enable });
      renderSchedules();
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptDelSchedule = async (id) => {
    if (!confirm("Delete schedule #" + id + "?")) return;
    try { await API.del(`/api/schedules/${id}`); toast("Deleted"); renderSchedules(); }
    catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Scan detail ----------
  window.ptOpenScan = (id) => {
    stopPolling(); setActiveNav("scans");
    if (window.location.pathname !== "/scans/" + id) history.pushState({}, "", "/scans/" + id);
    renderScanDetail(id);
  };
  async function renderScanDetail(id) {
    view.innerHTML = loading();
    try {
      const scan = await API.get(`/api/scans/${id}`);
      const [findings, webFindings] = await Promise.all([
        API.get(`/api/scans/${id}/findings`),
        API.get(`/api/scans/${id}/web-findings`),
      ]);

      // Show only the sections relevant to this scan type (avoid empty "Web findings",
      // "Discovered hosts", etc. on scans that never produce them).
      const t = scan.scan_type;
      const isWeb = ["web", "zap_passive", "zap_active"].includes(t);
      const isNet = ["discovery", "port", "full", "custom"].includes(t);
      const isCred = t === "credentialed";
      const isCis = t === "cis_benchmark";
      const showCve = isCred || t === "full" || t === "custom" || findings.length > 0;
      const showWeb = isWeb || webFindings.length > 0;

      const FIND_CAP = 300;
      const findRows = findings.slice(0, FIND_CAP).map((f) => `
        <tr>
          <td class="nowrap"><a onclick="ptViewCve('${esc(f.cve_id)}')">${esc(f.cve_id)}</a>${f.kev ? ' <span class="sev-badge sev-critical" title="CISA Known Exploited Vulnerability — actively exploited">KEV</span>' : ""}</td>
          <td>${esc(f.package || "—")}</td>
          <td>${sevBadge(f.severity)}</td>
          <td>${f.cvss_score ?? "—"}</td>
          <td class="nowrap small">${f.epss_score != null ? (f.epss_score * 100).toFixed(1) + "%" : "—"}</td>
          <td>${esc(f.match_confidence)}<br><span class="muted small">${esc(f.match_reason)}</span></td>
          <td>
            <select class="btn-sm" onchange="ptSetFindingStatus(${f.id}, this.value)">
              ${["open","confirmed","false_positive","fixed","accepted"].map((s) =>
                `<option ${f.status===s?"selected":""}>${s}</option>`).join("")}
            </select>
          </td></tr>`).join("") ||
        `<tr><td colspan="7" class="empty">No CVE findings correlated.</td></tr>`;

      const webRows = webFindings.map((w) => `
        <tr>
          <td><b>${esc(w.name)}</b>${w.cve_id ? ` <a onclick="ptViewCve('${esc(w.cve_id)}')">${esc(w.cve_id)}</a>` : ""}
            <br><span class="muted small">${esc(w.description)}</span>
            ${w.evidence ? `<br><span class="muted small mono">${esc(w.evidence)}</span>` : ""}</td>
          <td>${esc(w.category)}</td>
          <td>${sevBadge(w.severity)}</td>
          <td class="small">${esc(w.remediation)}</td>
        </tr>`).join("") ||
        `<tr><td colspan="4" class="empty">No web findings.</td></tr>`;

      // Discovered hosts & open ports (network scans). The API returns hosts[].services[];
      // package-audit "services" (protocol "pkg") are excluded — they have their own table.
      const showHosts = Array.isArray(scan.hosts) && scan.hosts.length > 0 && isNet;
      let openPortCount = 0;
      let hostRows = "";
      if (showHosts) {
        hostRows = scan.hosts.map((h) => {
          const svcs = (h.services || []).filter((s) => s.protocol !== "pkg");
          const hostCell = `${esc(h.address)}${h.hostname ? ` <span class="muted small">(${esc(h.hostname)})</span>` : ""}${h.os_guess ? `<br><span class="muted small">${esc(h.os_guess)}</span>` : ""}`;
          if (!svcs.length) {
            return `<tr><td>${hostCell}</td><td colspan="4" class="muted small">host up — no open ports detected</td></tr>`;
          }
          return svcs.map((s, i) => {
            openPortCount++;
            const ver = [s.product, s.version].filter(Boolean).join(" ") || s.banner || "—";
            return `<tr>
              <td>${i === 0 ? hostCell : ""}</td>
              <td class="mono nowrap">${s.port}/${esc(s.protocol)}</td>
              <td>${esc(s.state)}</td>
              <td>${esc(s.service_name || "—")}</td>
              <td class="small">${esc(ver)}</td>
            </tr>`;
          }).join("");
        }).join("");
      }

      view.innerHTML = pageHead("activity",
        `Scan #${scan.id} <span class="muted" style="font-size:14px">${esc(scan.scan_type)}</span>`,
        `<button class="btn" onclick="ptRoute('scans')">← Back</button>`
        + ((scan.status === "running" || scan.status === "queued") ? `<button class="btn" onclick="ptCancelScan(${scan.id})">⏹ Stop</button>` : "")
        + `<button class="btn" onclick="ptRescan(${scan.target_id}, '${esc(scan.scan_type)}')">🔄 Rescan</button>`
        + `<button class="btn btn-primary" onclick="ptDownload(${scan.id},'pdf')">⬇ PDF report</button>`
        + `<button class="btn btn-primary" onclick="ptDownload(${scan.id},'csv')">⬇ CSV report</button>`
        + (scan.scan_type === "credentialed" ? `<button class="btn" onclick="ptDownloadPkgs(${scan.id})">⬇ Package inventory CSV</button>` : "")
        + `<button class="btn" onclick="ptEmailScan(${scan.id})">✉ Email report</button>`) + `
        <div class="card">
          <div class="detail-grid">
            <span class="k">Status</span><span id="scan-status">${statusBadge(scan.status)} ${scan.status==="running"?scan.progress+"%":""}</span>
            <span class="k">nmap profile</span><span class="mono">${esc(scan.profile || "—")}</span>
            <span class="k">Started</span><span>${fmtDate(scan.started_at)}</span>
            <span class="k">Finished</span><span>${fmtDate(scan.finished_at)}</span>
            <span class="k">Operator</span><span>${esc(scan.created_by)}</span>
            ${scan.error ? `<span class="k">Error</span><span style="color:#ff6b6b">${esc(scan.error)}</span>` : ""}
          </div>
        </div>
        <div id="scan-charts" class="chart-row"></div>
        <h3 class="section-title">Live scan log <span id="log-live"></span></h3>
        <pre id="scan-console" class="console"></pre>
        ${showHosts ? `
        <h3 class="section-title">Discovered hosts &amp; open ports (${scan.hosts.length} host${scan.hosts.length === 1 ? "" : "s"}${scan.scan_type !== "discovery" ? `, ${openPortCount} open port${openPortCount === 1 ? "" : "s"}` : ""})</h3>
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:26%"><col style="width:13%"><col style="width:10%"><col style="width:19%"><col style="width:32%"></colgroup>
          <thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Product / version</th></tr></thead>
          <tbody>${hostRows || `<tr><td colspan="5" class="empty">No hosts up.</td></tr>`}</tbody></table></div>` : ""}
        ${showCve ? `
        <h3 class="section-title">CVE findings (${findings.length})</h3>
        ${findings.length > FIND_CAP ? `<p class="muted small">Showing first ${FIND_CAP}. Use the Reports page or CSV export for the full set.</p>` : ""}
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:15%"><col style="width:13%"><col style="width:9%"><col style="width:6%"><col style="width:6%"><col style="width:36%"><col style="width:15%"></colgroup>
          <thead><tr><th>CVE</th><th>Package / service</th><th>Severity</th><th>CVSS</th><th title="EPSS: probability of exploitation in next 30 days">EPSS</th><th>Match / fix</th><th>Status</th></tr></thead>
          <tbody>${findRows}</tbody></table></div>` : ""}
        ${showWeb ? `
        <h3 class="section-title">Web / URL findings (${webFindings.length})</h3>
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:40%"><col style="width:14%"><col style="width:10%"><col style="width:36%"></colgroup>
          <thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Remediation</th></tr></thead>
          <tbody>${webRows}</tbody></table></div>` : ""}
        ${scan.scan_type === "cis_benchmark" ? `
        <h3 class="section-title" style="margin-top:22px">CIS benchmark / hardening results <span id="cfg-count" class="muted small"></span></h3>
        <div id="cfg-box">${loading()}</div>` : ""}
        ${scan.scan_type === "credentialed" ? `
        <div class="page-head" style="margin-top:22px;margin-bottom:8px">
          <h3 class="section-title" style="margin:0">Installed package inventory</h3>
          <label class="muted small"><input type="checkbox" id="pkg-vuln-only" style="width:auto" onchange="ptLoadPackages(${scan.id})"> show vulnerable only</label>
        </div>
        <input id="pkg-q" placeholder="Filter packages by name…" style="margin-bottom:8px" oninput="ptDebouncePkgs(${scan.id})">
        <div id="pkg-box">${loading()}</div>` : ""}`;

      if (scan.scan_type === "cis_benchmark") ptLoadConfigFindings(scan.id);
      if (scan.scan_type === "credentialed") ptLoadPackages(scan.id);

      // Severity charts for vulnerability findings (CIS gets its own charts on load).
      if (scan.scan_type !== "cis_benchmark") {
        const all = [...findings, ...webFindings];
        const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
        const counts = {}; all.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
        const segs = order.map(s => ({ label: s, value: counts[s] || 0, color: SEV_COLOR[s] }));
        const box = document.getElementById("scan-charts");
        if (box && all.length) {
          box.innerHTML =
            chartCard("Findings by severity",
              `<div class="donut-wrap">${svgDonut(segs, String(all.length), "findings")}${legend(segs)}</div>`)
            + chartCard("Severity distribution", svgBars(segs.filter(s => s.value > 0)));
        }
      }

      // Load the live log (and keep streaming it while the scan runs).
      logOffset = 0;
      ptLoadLog(id);
      const running = scan.status === "queued" || scan.status === "running";
      const liveEl = document.getElementById("log-live");
      if (liveEl && running) liveEl.innerHTML = '<span class="live-dot"></span>';

      // While running, poll status + log in place (no full re-render → no flicker).
      // Do one final full render when the scan finishes.
      if (running) {
        pollTimer = setInterval(async () => {
          try {
            const s = await API.get(`/api/scans/${id}`);
            const el = document.getElementById("scan-status");
            if (!el) { stopPolling(); return; }  // navigated away
            el.innerHTML = statusBadge(s.status) + (s.status === "running" ? " " + s.progress + "%" : "");
            await ptLoadLog(id);
            if (s.status === "completed" || s.status === "failed") {
              stopPolling();
              renderScanDetail(id);  // single clean render with the results
            }
          } catch (ex) { stopPolling(); }
        }, 3000);
      }
    } catch (ex) { view.innerHTML = errBox(ex); }
  }
  let logOffset = 0;
  window.ptLoadLog = async (id) => {
    const con = document.getElementById("scan-console");
    if (!con) return;
    try {
      const d = await API.get(`/api/scans/${id}/log?offset=${logOffset}`);
      if (d.chunk) {
        con.textContent += d.chunk;
        logOffset = d.offset;
        con.scrollTop = con.scrollHeight;
      }
    } catch (ex) { /* ignore transient log poll errors */ }
  };
  window.ptEmailScan = (id) => {
    modal("Email scan report", `
      <div class="form-row"><label>Recipients (comma-separated)</label>
        <input id="em-rcpt" placeholder="leave blank to use the configured default recipients"></div>
      <div class="form-row"><label>Attachments</label>
        <label class="chk"><input type="checkbox" id="em-pdf" checked> PDF</label>
        <label class="chk"><input type="checkbox" id="em-csv" checked> CSV</label></div>
      <button class="btn btn-primary btn-block" onclick="ptSendEmail(${id})">Send</button>
      <p class="muted small" style="margin-top:8px">Configure SMTP under Settings first. The email body includes the severity summary.</p>`);
  };
  window.ptSendEmail = async (id) => {
    const formats = [];
    if (document.getElementById("em-pdf").checked) formats.push("pdf");
    if (document.getElementById("em-csv").checked) formats.push("csv");
    const recipients = document.getElementById("em-rcpt").value.trim() || null;
    try {
      const r = await API.post(`/api/reports/scan/${id}/email`, { recipients, formats });
      closeModal(); toast(`Emailed to ${r.recipients.join(", ")} (${r.total_findings} findings)`);
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptSetFindingStatus = async (id, status) => {
    try { await API.patch(`/api/findings/${id}`, { status }); toast("Updated"); }
    catch (ex) { toast(ex.message, "err"); }
  };
  window.ptDownload = (id, fmt) =>
    API.download(`/api/reports/scan/${id}/${fmt}`, `scan_${id}_report.${fmt}`)
      .catch((ex) => toast(ex.message, "err"));
  window.ptDownloadPkgs = (id) =>
    API.download(`/api/reports/scan/${id}/packages.csv`, `scan_${id}_package_inventory.csv`)
      .catch((ex) => toast(ex.message, "err"));

  window.ptLoadConfigFindings = async (id) => {
    const box = document.getElementById("cfg-box");
    if (!box) return;
    try {
      const data = await API.get(`/api/scans/${id}/config-findings`);
      const cnt = document.getElementById("cfg-count");
      // The audit-summary row carries the mode (OpenSCAP/built-in) + compliance score.
      const summary = data.findings.find((f) => f.check_id === "audit-summary");
      const findings = data.findings.filter((f) => f.check_id !== "audit-summary");
      if (!findings.length) {
        if (cnt) cnt.textContent = "";
        box.innerHTML = `<p class="muted small">No hardening data (older scan, or checks could not run).</p>`;
        return;
      }
      const m = data.cis || {};
      if (cnt) cnt.innerHTML = `· <b style="color:var(--high)">${data.fails} failed</b> of ${findings.length}`
        + ` · <span class="muted">${esc(m.distro || "")} · ${esc(m.level || "")}</span>`;

      // CIS charts: compliance-score donut + pass/fail + failed-by-severity.
      const cbox = document.getElementById("scan-charts");
      if (cbox) {
        const passN = findings.filter(f => f.status === "pass").length;
        const failN = findings.filter(f => f.status === "fail").length;
        const scoreM = (summary && /score ([\d.]+)%/.exec(summary.detail || "")) || null;
        const score = scoreM ? Math.round(parseFloat(scoreM[1])) : Math.round(passN / Math.max(1, passN + failN) * 100);
        const pf = [{ label: "pass", value: passN, color: "#2e7d32" }, { label: "fail", value: failN, color: "#c0392b" }];
        const order = ["HIGH", "MEDIUM", "LOW", "INFO"];
        const fc = {}; findings.filter(f => f.status === "fail").forEach(f => { fc[f.severity] = (fc[f.severity] || 0) + 1; });
        const sevSegs = order.map(s => ({ label: s, value: fc[s] || 0, color: SEV_COLOR[s] })).filter(s => s.value > 0);
        cbox.innerHTML =
          chartCard("CIS compliance score",
            svgDonut([{ value: score, color: (score >= 80 ? "#2e7d32" : score >= 50 ? "#e67e22" : "#c0392b") },
                      { value: 100 - score, color: "var(--border)" }], score + "%", "compliant"))
          + chartCard("Controls pass / fail",
            `<div class="donut-wrap">${svgDonut(pf, String(passN + failN), "controls")}${legend(pf)}</div>`)
          + (sevSegs.length ? chartCard("Failed controls by severity", svgBars(sevSegs)) : "");
      }

      const rows = findings.map((f) => {
        const st = f.status === "fail"
          ? sevBadge(f.severity)
          : (f.status === "pass" ? '<span class="status-badge status-completed">pass</span>'
                                 : '<span class="status-badge">n/a</span>');
        return `<tr>
          <td>${st}</td>
          <td><b>${esc(f.title)}</b><br><span class="muted small">${esc(f.detail)}</span>
            ${f.evidence ? `<br><span class="muted small mono">${esc(f.evidence.slice(0, 160))}</span>` : ""}</td>
          <td class="small">${f.status === "fail" ? esc(f.remediation) : "—"}</td>
        </tr>`;
      }).join("");
      const banner = `<div class="cis-banner">
        <div class="cis-chip"><span class="k">Distro</span><span class="v">${esc(m.distro || "unknown")}</span></div>
        <div class="cis-chip"><span class="k">Benchmark level</span><span class="v">${esc(m.level || "—")}</span></div>
        <div class="cis-chip"><span class="k">Engine</span><span class="v">${esc(m.engine || "—")}</span></div>
        ${m.score != null ? `<div class="cis-chip score"><span class="k">Compliance</span><span class="v">${m.score}%</span></div>` : ""}
        <div class="cis-chip"><span class="k">Controls failed</span><span class="v" style="color:var(--high)">${data.fails} / ${findings.length}</span></div>
      </div>`;
      box.innerHTML = banner + `<div class="table-wrap"><table class="fixed">
        <colgroup><col style="width:12%"><col style="width:55%"><col style="width:33%"></colgroup>
        <thead><tr><th>Result</th><th>Check</th><th>Remediation</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) { box.innerHTML = errBox(ex); }
  };

  let pkgDebounce = null;
  window.ptDebouncePkgs = (id) => { clearTimeout(pkgDebounce); pkgDebounce = setTimeout(() => ptLoadPackages(id), 300); };
  window.ptLoadPackages = async (id) => {
    const box = document.getElementById("pkg-box");
    if (!box) return;
    const onlyVuln = document.getElementById("pkg-vuln-only")?.checked ? "true" : "false";
    const q = document.getElementById("pkg-q")?.value.trim() || "";
    box.innerHTML = loading();
    try {
      const params = new URLSearchParams({ only_vulnerable: onlyVuln });
      if (q) params.set("q", q);
      const data = await API.get(`/api/scans/${id}/packages?` + params.toString());
      const PKG_CAP = 500;
      const rows = data.packages.slice(0, PKG_CAP).map((p) => `
        <tr>
          <td><b>${esc(p.name)}</b></td>
          <td class="mono">${esc(p.full_version || p.version)}</td>
          <td>${p.status === "vulnerable" ? sevBadge(p.max_severity) : '<span class="status-badge status-completed">ok</span>'}</td>
          <td>${p.max_cvss ?? "—"}</td>
          <td class="small">${p.cve_ids ? p.cve_ids.split(", ").map((c) => `<a onclick="ptViewCve('${esc(c)}')">${esc(c)}</a>`).join(", ") : "—"}</td>
          <td class="small">${esc(p.remediation)}</td>
        </tr>`).join("") || `<tr><td colspan="6" class="empty">No packages.</td></tr>`;
      box.innerHTML = `<div class="muted small" style="margin-bottom:6px">${data.total} packages · <b style="color:var(--high)">${data.vulnerable} vulnerable</b>${data.total > PKG_CAP ? ` · showing first ${PKG_CAP} (download CSV for all)` : ""}</div>
        <div class="table-wrap"><table>
        <thead><tr><th>Package</th><th>Version</th><th>Criticality</th><th>Max CVSS</th><th>CVEs</th><th>Patching remedy</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) { box.innerHTML = errBox(ex); }
  };

  // ---------- CVEs ----------
  async function renderCves() {
    view.innerHTML = pageHead("cves", "CVE Database",
      `<button class="btn" onclick="ptExportCveDb()">⬇ Download CVE DB</button>
        <button class="btn admin-only" onclick="document.getElementById('cve-upload-file').click()">⬆ Upload CVE DB</button>
        <button class="btn btn-primary admin-only" onclick="ptImportFeeds()">⬆ Import NVD feeds</button>
        <button class="btn admin-only" onclick="ptImportThreatIntel()" title="Enrich CVEs with CISA KEV (exploited-in-the-wild) + FIRST EPSS scores">🎯 Import KEV / EPSS</button>
        <button class="btn admin-only" onclick="ptImportDistroFeeds()" title="Import vendor advisories (OVAL / Debian JSON) for backport-aware package matching">🐧 Import distro feeds</button>
        <input type="file" id="cve-upload-file" accept=".json,.gz,.json.gz,.json.xz" style="display:none" onchange="ptUploadCveDb(this)">`)
      + `<div class="toolbar">
          <input id="cve-q" placeholder="Search CVE id, description, product…" style="min-width:240px">
          <input id="cve-product" placeholder="Affected package / product…" style="min-width:180px">
          <select id="cve-sev">
            <option value="">All severities</option>
            <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
          </select>
          <select id="cve-cwe" title="Filter by vulnerability type (CWE)">
            <option value="">All vulnerability types</option>
            <option value="CWE-79">Cross-Site Scripting (XSS) · CWE-79</option>
            <option value="CWE-89">SQL Injection · CWE-89</option>
            <option value="CWE-78">OS Command Injection · CWE-78</option>
            <option value="CWE-22">Path Traversal · CWE-22</option>
            <option value="CWE-352">CSRF · CWE-352</option>
            <option value="CWE-918">SSRF · CWE-918</option>
            <option value="CWE-787">Out-of-bounds Write · CWE-787</option>
            <option value="CWE-125">Out-of-bounds Read · CWE-125</option>
            <option value="CWE-416">Use After Free · CWE-416</option>
            <option value="CWE-190">Integer Overflow · CWE-190</option>
            <option value="CWE-502">Deserialization · CWE-502</option>
            <option value="CWE-434">Unrestricted File Upload · CWE-434</option>
            <option value="CWE-287">Improper Authentication · CWE-287</option>
            <option value="CWE-269">Improper Privilege Mgmt · CWE-269</option>
            <option value="CWE-20">Improper Input Validation · CWE-20</option>
          </select>
          <label class="muted small" style="display:inline-flex;align-items:center;gap:4px"><input type="checkbox" id="cve-kev" style="width:auto"> 🎯 Exploited (KEV) only</label>
          <button class="btn btn-primary" onclick="ptSearchCves()">Search</button>
          <span id="cve-count" class="muted small"></span>
        </div>
        <div id="cve-autoupdate" class="card" style="margin-bottom:16px"></div>
        <div id="cve-results">${loading()}</div>`;
    document.querySelectorAll(".admin-only").forEach((el) => {
      el.style.display = (API.user() || {}).role === "admin" ? "" : "none";
    });
    document.getElementById("cve-q").addEventListener("keydown", (e) => { if (e.key === "Enter") ptSearchCves(); });
    document.getElementById("cve-product").addEventListener("keydown", (e) => { if (e.key === "Enter") ptSearchCves(); });
    document.getElementById("cve-sev").addEventListener("change", ptSearchCves);
    document.getElementById("cve-cwe").addEventListener("change", ptSearchCves);
    document.getElementById("cve-kev").addEventListener("change", ptSearchCves);
    try {
      const c = await API.get("/api/cves/count");
      document.getElementById("cve-count").textContent = `${c.total} CVEs in local database`;
    } catch {}
    ptLoadAutoUpdate();
    ptSearchCves();
  }
  window.ptLoadAutoUpdate = async () => {
    const box = document.getElementById("cve-autoupdate");
    if (!box) return;
    const isAdmin = (API.user() || {}).role === "admin";
    try {
      const c = await API.get("/api/cves/update/config");
      const statusColor = { ok: "var(--ok)", error: "var(--high)", running: "var(--med)", never: "var(--muted)" }[c.last_status] || "var(--muted)";
      box.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
          <div>
            <b>🔄 Automatic CVE updates</b>
            <div class="muted small" style="margin-top:4px">
              Last run: ${c.last_run ? fmtDate(c.last_run) : "never"} ·
              status: <span style="color:${statusColor}">${esc(c.last_status)}</span>
              ${c.last_added ? ` · +${c.last_added} added` : ""}
              ${c.last_message ? `<br>${esc(c.last_message)}` : ""}
            </div>
          </div>
          <div class="pill-row" style="align-items:center">
            <label class="chk"><input type="checkbox" id="au-enabled" ${c.enabled ? "checked" : ""} ${isAdmin ? "" : "disabled"}> Enabled</label>
            every <input id="au-interval" type="number" value="${c.interval_hours}" style="width:64px" ${isAdmin ? "" : "disabled"}> h
            <select id="au-source" ${isAdmin ? "" : "disabled"}>
              <option value="online" ${c.source === "online" ? "selected" : ""}>Online (NVD mirror)</option>
              <option value="feed_dir" ${c.source === "feed_dir" ? "selected" : ""}>Feed directory (offline)</option>
            </select>
            ${isAdmin ? `<button class="btn btn-sm btn-primary" onclick="ptSaveAutoUpdate()">Save</button>
            <button class="btn btn-sm" onclick="ptRunUpdateNow()">Update now</button>` : ""}
          </div>
        </div>`;
    } catch (ex) { box.innerHTML = `<span class="muted small">Auto-update status unavailable: ${esc(ex.message)}</span>`; }
  };
  window.ptSaveAutoUpdate = async () => {
    try {
      await API.put("/api/cves/update/config", {
        enabled: document.getElementById("au-enabled").checked,
        interval_hours: parseInt(document.getElementById("au-interval").value, 10) || 24,
        source: document.getElementById("au-source").value,
      });
      toast("Auto-update settings saved"); ptLoadAutoUpdate();
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptRunUpdateNow = async () => {
    toast("Running CVE update… (online download may take a moment)");
    try {
      const r = await API.post("/api/cves/update/run");
      toast(r.message || `Update done (+${r.imported})`);
      ptLoadAutoUpdate();
      const c = await API.get("/api/cves/count");
      const el = document.getElementById("cve-count"); if (el) el.textContent = `${c.total} CVEs in local database`;
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptSearchCves = async () => {
    const q = document.getElementById("cve-q").value.trim();
    const product = document.getElementById("cve-product").value.trim();
    const sev = document.getElementById("cve-sev").value;
    const cwe = document.getElementById("cve-cwe").value;
    const box = document.getElementById("cve-results");
    box.innerHTML = loading();
    try {
      const params = new URLSearchParams();
      if (q) params.set("q", q);
      if (product) params.set("product", product);
      if (sev) params.set("severity", sev);
      if (cwe) params.set("cwe", cwe);
      if (document.getElementById("cve-kev").checked) params.set("kev_only", "true");
      params.set("sort", (window._tool || {}).match_default_sort || "risk");
      params.set("limit", "200");
      const cves = await API.get("/api/cves?" + params.toString());
      const rows = cves.map((c) => `
        <tr onclick="ptViewCve('${esc(c.cve_id)}')" style="cursor:pointer">
          <td class="mono nowrap">${esc(c.cve_id)}${c.kev ? ' <span class="sev-badge sev-critical" title="CISA Known Exploited Vulnerability">KEV</span>' : ""}</td>
          <td>${sevBadge(c.severity)}</td>
          <td>${c.cvss_v3_score ?? "—"}</td>
          <td class="nowrap small">${c.epss_score != null ? (c.epss_score * 100).toFixed(1) + "%" : "—"}</td>
          <td class="nowrap small">${esc(c.cwe || "—")}</td>
          <td>${esc((c.description || "").slice(0, 110))}…</td></tr>`).join("") ||
        `<tr><td colspan="6" class="empty">No matching CVEs.</td></tr>`;
      box.innerHTML = `<div class="table-wrap"><table>
        <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th title="EPSS: probability of exploitation in next 30 days">EPSS</th><th>Type (CWE)</th><th>Description</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) { box.innerHTML = errBox(ex); }
  };
  window.ptViewCve = async (cveId) => {
    modal(cveId, loading());
    try {
      const c = await API.get(`/api/cves/${cveId}`);
      document.getElementById("modal-body").innerHTML = `
        <div class="detail-grid">
          <span class="k">Severity</span><span>${sevBadge(c.severity)}</span>
          <span class="k">CVSS v3</span><span>${c.cvss_v3_score ?? "—"} <span class="muted mono small">${esc(c.cvss_v3_vector)}</span></span>
          <span class="k">CWE</span><span>${esc(c.cwe || "—")}</span>
          <span class="k">Published</span><span>${fmtDate(c.published)}</span>
        </div>
        <h4 class="section-title">Description</h4><p>${esc(c.description)}</p>
        <h4 class="section-title">Remediation</h4><p>${esc(c.remediation)}</p>
        ${c.cpe_products ? `<h4 class="section-title">Affected products</h4><p class="mono small">${esc(c.cpe_products.split("|").slice(0,30).join(", "))}</p>` : ""}
        ${c.references ? `<h4 class="section-title">References</h4>${c.references.split("\n").filter(Boolean).map((r)=>`<div class="small mono">${esc(r)}</div>`).join("")}` : ""}`;
    } catch (ex) { document.getElementById("modal-body").innerHTML = errBox(ex); }
  };
  window.ptImportFeeds = async () => {
    toast("Importing feeds from /data/cve_feeds … this may take a while");
    try {
      const r = await API.post("/api/cves/import");
      toast(r.message);
      renderCves();
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptImportDistroFeeds = async () => {
    toast("Importing distro security advisories from /data/cve_feeds/distro_feeds …");
    try {
      let r = await API.post("/api/cves/distro-feeds/import");
      // If no local feed files were present, offer to download them online.
      if ((r.files || 0) === 0) {
        if (confirm("No distro advisory feeds found in /data/cve_feeds/distro_feeds.\n\n"
            + "Download the vendor OVAL feeds online now? (RHEL 8/9, Oracle Linux, "
            + "Ubuntu LTS — needs internet, use only on a connected host.)\n\n"
            + "The downloaded files are saved to data/cve_feeds/distro_feeds/ so you can "
            + "copy that folder to an air-gapped host and import there offline.")) {
          toast("Downloading vendor OVAL feeds online… (large, give it a minute)");
          r = await API.post("/api/cves/distro-feeds/import?online=true");
        }
      }
      toast(r.message || "Distro feeds imported");
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptImportThreatIntel = async () => {
    toast("Importing KEV + EPSS from /data/cve_feeds … enriching existing CVEs");
    try {
      let r = await API.post("/api/cves/threat-intel/import");
      // If no local feed files were present, offer to fetch them online.
      if ((r.kev_updated || 0) === 0 && (r.epss_updated || 0) === 0
          && /no (KEV|EPSS) file/i.test(r.message || "")) {
        if (confirm("No KEV/EPSS files found in /data/cve_feeds.\n\nFetch them online now? "
            + "(needs internet — use this only on a connected host; on an air-gapped host, "
            + "drop known_exploited_vulnerabilities.json and epss_scores-current.csv.gz in "
            + "data/cve_feeds/ instead.)")) {
          toast("Fetching KEV + EPSS online… (EPSS is ~250k rows, give it a moment)");
          r = await API.post("/api/cves/threat-intel/import?online=true");
        }
      }
      toast(r.message || "Threat-intel imported");
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptExportCveDb = () => {
    const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    toast("Preparing CVE database export… (large databases take a moment)");
    API.download("/api/cves/export", `threatprobe-cve-db-${stamp}.json.gz`)
      .catch((ex) => toast(ex.message, "err"));
  };
  window.ptUploadCveDb = async (input) => {
    const f = input.files && input.files[0];
    input.value = "";  // allow re-selecting the same file later
    if (!f) return;
    toast(`Uploading ${f.name} … importing on the server may take a while`);
    try {
      const fd = new FormData();
      fd.append("file", f);
      const r = await API.postForm("/api/cves/upload", fd);
      toast(r.message || "CVE database imported");
      renderCves();
    } catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Reports (filtered, consolidated export) ----------
  function checkGroup(name, opts) {
    return opts.map((o) => {
      const val = typeof o === "string" ? o : o.v;
      const lbl = typeof o === "string" ? o : o.l;
      return `<label class="chk"><input type="checkbox" name="${name}" value="${esc(val)}"> ${esc(lbl)}</label>`;
    }).join("");
  }
  async function renderReports() {
    view.innerHTML = pageHead("reports", "Reports") + loading();
    let targets = [];
    try { targets = await API.get("/api/targets"); } catch (ex) { view.innerHTML = errBox(ex); return; }
    const targetOpts = `<option value="">All scans / all targets</option>` +
      targets.map((t) => `<option value="${t.id}">${esc(t.name)} (${esc(t.address)})</option>`).join("");
    view.innerHTML = pageHead("reports", "Reports",
      `<span class="muted small">Build a consolidated, filtered report across scans</span>`) + `
      <div class="card">
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">
          <div class="form-row"><label>Scope (target)</label><select id="rp-target">${targetOpts}</select></div>
          <div class="form-row"><label>Finding types</label><div class="chk-group">${checkGroup("rp-types", [{v:"cve",l:"Server/CVE"},{v:"web",l:"Web/URL"},{v:"package",l:"Package"}])}</div></div>
          <div class="form-row"><label>Severity</label><div class="chk-group">${checkGroup("rp-sev", ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])}</div></div>
          <div class="form-row"><label>Triage status</label><div class="chk-group">${checkGroup("rp-status", ["open","confirmed","false_positive","fixed","accepted"])}</div></div>
          <div class="form-row"><label>Match confidence</label><div class="chk-group">${checkGroup("rp-conf", ["high","medium","low"])}</div></div>
          <div class="form-row"><label>Host / IP contains</label><input id="rp-host" placeholder="e.g. 172.20 or app.local"></div>
          <div class="form-row"><label>Port</label><input id="rp-port" type="number" placeholder="e.g. 443"></div>
          <div class="form-row"><label>CVE id contains</label><input id="rp-cve" placeholder="e.g. CVE-2021-44228"></div>
          <div class="form-row"><label>Package name contains</label><input id="rp-pkg" placeholder="e.g. openssl"></div>
          <div class="form-row"><label>&nbsp;</label><label class="chk"><input type="checkbox" id="rp-vuln"> Vulnerable packages only</label></div>
        </div>
        <div class="toolbar" style="margin-top:6px;align-items:center">
          <button class="btn btn-primary" onclick="ptReportPreview()">↻ Apply filters</button>
          <button class="btn btn-primary" onclick="ptReportDownload('pdf')">⬇ Download PDF</button>
          <button class="btn btn-primary" onclick="ptReportDownload('csv')">⬇ Download CSV</button>
          <span id="rp-preview" class="muted small"></span>
        </div>
        <p class="muted small">Leave a filter empty to include everything for that dimension. No filters ⇒ full consolidated report across all scans.</p>
      </div>
      <div id="rp-breakdown"></div>
      <div id="rp-results"></div>`;
    ptReportPreview();
  }
  function ptReportQuery() {
    const vals = (name) => Array.from(document.querySelectorAll(`input[name="${name}"]:checked`)).map((e) => e.value);
    const p = new URLSearchParams();
    const tid = document.getElementById("rp-target").value;
    if (tid) p.set("target_id", tid);
    const sev = vals("rp-sev"); if (sev.length) p.set("severity", sev.join(","));
    const st = vals("rp-status"); if (st.length) p.set("status", st.join(","));
    const ty = vals("rp-types"); if (ty.length) p.set("types", ty.join(","));
    const cf = vals("rp-conf"); if (cf.length) p.set("confidence", cf.join(","));
    const host = document.getElementById("rp-host").value.trim(); if (host) p.set("host", host);
    const port = document.getElementById("rp-port").value.trim(); if (port) p.set("port", port);
    const cve = document.getElementById("rp-cve").value.trim(); if (cve) p.set("cve_id", cve);
    const pkg = document.getElementById("rp-pkg").value.trim(); if (pkg) p.set("package", pkg);
    if (document.getElementById("rp-vuln").checked) p.set("vulnerable_only", "true");
    return p.toString();
  }
  window.ptReportPreview = async () => {
    const box = document.getElementById("rp-preview");
    const bd = document.getElementById("rp-breakdown");
    const res = document.getElementById("rp-results");
    box.textContent = "filtering…";
    res.innerHTML = loading();
    try {
      const data = await API.get("/api/reports/export/results?limit=1000&" + ptReportQuery());
      const c = data.meta.counts;
      box.innerHTML = `<b style="color:var(--text)">${c.total}</b> findings (CVE ${c.cve}, Web ${c.web}, Package ${c.package})`;
      const sev = data.meta.severity_breakdown || {};
      const colors = { CRITICAL:"var(--crit)",HIGH:"var(--high)",MEDIUM:"var(--med)",LOW:"var(--low)",INFO:"var(--info)",NONE:"var(--info)",UNKNOWN:"var(--info)" };
      const bar = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","UNKNOWN"].filter((k)=>sev[k])
        .map((k)=>`<div style="background:${colors[k]};flex:${sev[k]}" title="${k}: ${sev[k]}">${sev[k]}</div>`).join("");
      bd.innerHTML = bar ? `<h3 class="section-title">Matching severity breakdown</h3><div class="sev-bar">${bar}</div>` : "";

      const rows = (data.rows || []).map((r) => `
        <tr>
          <td>${sevBadge(r.severity)}</td>
          <td>${esc(r.type)}</td>
          <td>${esc(r.target)}</td>
          <td class="mono small">${esc(r.location)}</td>
          <td><b>${esc(r.name)}</b><br><span class="muted small">${esc(r.detail || "")}</span></td>
          <td>${esc(r.status || "")}</td>
          <td class="small">${esc(r.remediation || "")}</td>
        </tr>`).join("") || `<tr><td colspan="7" class="empty">No findings match these filters.</td></tr>`;
      res.innerHTML = `<h3 class="section-title">Filtered findings (${data.shown}${data.truncated ? "+ — refine filters or use CSV for all" : ""})</h3>
        <div class="table-wrap"><table class="fixed">
        <colgroup><col style="width:9%"><col style="width:7%"><col style="width:14%"><col style="width:15%"><col style="width:26%"><col style="width:8%"><col style="width:21%"></colgroup>
        <thead><tr><th>Severity</th><th>Type</th><th>Target</th><th>Location</th><th>Finding</th><th>Status</th><th>Remediation</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) {
      box.innerHTML = `<span style="color:#ff6b6b">${esc(ex.message)}</span>`;
      res.innerHTML = "";
    }
  };
  window.ptReportDownload = (fmt) =>
    API.download(`/api/reports/export.${fmt}?` + ptReportQuery(), `vulnerability_report.${fmt}`)
      .catch((ex) => toast(ex.message, "err"));

  // ---------- Settings (SMTP / email) ----------
  // Render one app-settings field (input) from its registry definition.
  function settingField(it) {
    const id = `set-${it.key}`;
    const help = it.help ? `<div class="muted small" style="margin-top:3px">${esc(it.help)}</div>` : "";
    let input;
    if (it.type === "bool") {
      input = `<label class="chk"><input type="checkbox" id="${id}" ${it.value ? "checked" : ""}> ${esc(it.label)}</label>`;
      return `<div class="form-row">${input}${help}</div>`;
    } else if (it.type === "choice") {
      input = `<select id="${id}">${(it.choices || []).map((o) =>
        `<option ${String(it.value) === String(o) ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
    } else if (it.type === "int") {
      const mm = (it.min != null ? ` min="${it.min}"` : "") + (it.max != null ? ` max="${it.max}"` : "");
      input = `<input type="number" id="${id}" value="${esc(it.value)}"${mm}>`;
    } else if (it.type === "text") {
      input = `<textarea id="${id}" rows="3">${esc(it.value)}</textarea>`;
    } else {
      input = `<input type="text" id="${id}" value="${esc(it.value)}">`;
    }
    return `<div class="form-row"><label>${esc(it.label)}</label>${input}${help}</div>`;
  }

  function appGroupCard(g) {
    return `<div class="card" style="max-width:680px">
      <h3 class="section-title" style="margin-top:0">${esc(g.name)}</h3>
      ${g.items.map(settingField).join("")}
      <div class="pill-row" style="margin-top:6px">
        <button class="btn btn-primary" onclick="ptSaveAppGroup('${g.group}')">Save changes</button>
        <button class="btn" onclick="ptResetAppGroup('${g.group}','${esc(g.name)}')">↺ Reset to defaults</button>
      </div></div>`;
  }

  async function renderSettings() {
    view.innerHTML = pageHead("settings", "Settings") + loading();
    try {
      const [c, b, app] = await Promise.all([
        API.get("/api/settings/smtp"), API.get("/api/branding"), API.get("/api/settings/app"),
      ]);
      window._appGroups = app.groups;
      const isAdmin = (API.user() || {}).role === "admin";
      const brandingCard = `<div class="card" style="max-width:680px">
          <h3 class="section-title" style="margin-top:0">Branding</h3>
          <p class="muted small" style="margin-bottom:12px">Customize the application name and logo shown on the login page and sidebar (white-labelling).</p>
          <div class="form-row"><label>Application name</label><input id="br-name" value="${esc(b.app_name)}" placeholder="ThreatProbe Scanner"></div>
          <div class="form-row"><label>Logo emoji (used when no image is uploaded)</label><input id="br-emoji" value="${esc(b.logo_emoji)}" placeholder="🛡️" style="max-width:120px"></div>
          <div class="form-row"><label>Logo image (PNG / SVG / JPG, ~512&nbsp;KB max)</label>
            <input type="file" id="br-file" accept="image/png,image/svg+xml,image/jpeg" onchange="ptBrandPickLogo(this)"></div>
          <div class="form-row"><label>Current logo</label>
            <div id="br-preview" style="background:var(--bg-2);padding:10px;border-radius:8px">${b.logo_data_url ? `<img src="${esc(b.logo_data_url)}" style="height:48px">` : `<span style="font-size:40px">${esc(b.logo_emoji || "🛡️")}</span>`}</div></div>
          <div class="form-row"><label>Favicon (browser-tab icon — PNG/SVG/ICO)</label>
            <input type="file" id="br-fav-file" accept="image/png,image/svg+xml,image/x-icon,image/vnd.microsoft.icon,image/jpeg" onchange="ptBrandPickFavicon(this)"></div>
          <div class="form-row"><label>Current favicon</label>
            <div id="br-fav-preview" style="background:var(--bg-2);padding:10px;border-radius:8px">${b.favicon_data_url ? `<img src="${esc(b.favicon_data_url)}" style="height:32px">` : '<span class="muted small">none (uses logo / default)</span>'}</div></div>
          <div class="pill-row">
            <button class="btn btn-primary" onclick="ptSaveBranding()">Save branding</button>
            <button class="btn" onclick="ptClearLogo()">Remove uploaded logo</button>
          </div>
        </div>`;
      const smtpCard = `<div class="card" style="max-width:680px">
          <h3 class="section-title" style="margin-top:0">Email (SMTP)</h3>
          <p class="muted small" style="margin-bottom:12px">Configure SMTP here (stored in the database, not in files). Used to email scan reports with the findings summary in the body and PDF/CSV attached.</p>
          <div class="form-row"><label>SMTP host</label><input id="sm-host" value="${esc(c.host)}" placeholder="smtp.example.com"></div>
          <div class="grid" style="grid-template-columns:1fr 1fr">
            <div class="form-row"><label>Port</label><input id="sm-port" type="number" value="${c.port}"></div>
            <div class="form-row"><label>Encryption</label>
              <select id="sm-enc">
                <option value="tls" ${c.use_tls && !c.use_ssl ? "selected" : ""}>STARTTLS (587)</option>
                <option value="ssl" ${c.use_ssl ? "selected" : ""}>SSL/TLS (465)</option>
                <option value="none" ${!c.use_tls && !c.use_ssl ? "selected" : ""}>None</option>
              </select></div>
          </div>
          <div class="form-row"><label>Username</label><input id="sm-user" value="${esc(c.username)}" autocomplete="off"></div>
          <div class="form-row"><label>Password ${c.has_password ? "(leave blank to keep current)" : ""}</label><input id="sm-pass" type="password" autocomplete="new-password" placeholder="${c.has_password ? "••••••••" : ""}"></div>
          <div class="form-row"><label>From address</label><input id="sm-from" value="${esc(c.from_addr)}" placeholder="scanner@example.com"></div>
          <div class="form-row"><label>Default recipients (comma-separated)</label><input id="sm-rcpt" value="${esc(c.default_recipients)}" placeholder="soc@example.com, admin@example.com"></div>
          <div class="form-row"><label class="chk"><input type="checkbox" id="sm-enabled" ${c.enabled ? "checked" : ""}> Enable email features</label></div>
          <div class="pill-row">
            <button class="btn btn-primary" onclick="ptSaveSmtp()">Save</button>
            <button class="btn" onclick="ptTestSmtp()">Send test email</button>
          </div>
        </div>`;

      const tabs = [{ id: "general", name: "General" }, { id: "email", name: "Email" }]
        .concat(app.groups.map((g) => ({ id: g.group, name: g.name })));
      const tabBar = `<div class="tabs">${tabs.map((t, i) =>
        `<button class="tab ${i === 0 ? "active" : ""}" data-tab="${t.id}" onclick="ptSettingsTab('${t.id}')">${esc(t.name)}</button>`).join("")}</div>`;
      const panel = (id, html, first) =>
        `<div class="settings-panel ${first ? "" : "hidden"}" data-panel="${id}">${html}</div>`;
      const panels = panel("general", brandingCard, true)
        + panel("email", smtpCard, false)
        + app.groups.map((g) => panel(g.group, appGroupCard(g), false)).join("");
      const note = isAdmin ? "" : `<p class="muted small">Read-only — only admins can change settings.</p>`;
      view.innerHTML = pageHead("settings", "Settings") + tabBar + note
        + `<div id="settings-panels">${panels}</div>`;
    } catch (ex) { view.innerHTML = errBox(ex); }
  }
  window.ptSettingsTab = (id) => {
    document.querySelectorAll(".settings-panel").forEach((p) =>
      p.classList.toggle("hidden", p.dataset.panel !== id));
    document.querySelectorAll(".tab").forEach((b) =>
      b.classList.toggle("active", b.dataset.tab === id));
  };
  window.ptSaveAppGroup = async (group) => {
    const g = (window._appGroups || []).find((x) => x.group === group);
    if (!g) return;
    const values = {};
    g.items.forEach((it) => {
      const el = document.getElementById(`set-${it.key}`);
      if (!el) return;
      values[it.key] = it.type === "bool" ? el.checked : el.value;
    });
    try {
      const r = await API.put("/api/settings/app", { values });
      window._appGroups = r.groups;
      loadToolSettings(true);
      toast("Settings saved");
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptResetAppGroup = async (group, name) => {
    if (!confirm(`Reset "${name}" settings to their defaults?`)) return;
    try {
      await API.post(`/api/settings/app/reset/${group}`);
      loadToolSettings(true);
      toast(`${name} reset to defaults`);
      renderSettings();
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptSaveSmtp = async () => {
    const enc = document.getElementById("sm-enc").value;
    const body = {
      host: document.getElementById("sm-host").value.trim(),
      port: parseInt(document.getElementById("sm-port").value, 10) || 587,
      username: document.getElementById("sm-user").value.trim(),
      password: document.getElementById("sm-pass").value || null,
      from_addr: document.getElementById("sm-from").value.trim(),
      use_tls: enc === "tls", use_ssl: enc === "ssl",
      default_recipients: document.getElementById("sm-rcpt").value.trim(),
      enabled: document.getElementById("sm-enabled").checked,
    };
    try { await API.put("/api/settings/smtp", body); toast("SMTP settings saved"); renderSettings(); }
    catch (ex) { toast(ex.message, "err"); }
  };
  window.ptTestSmtp = async () => {
    toast("Sending test email…");
    try { const r = await API.post("/api/settings/smtp/test"); toast("Test email sent to " + r.recipients.join(", ")); }
    catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Branding ----------
  let _brandLogo = null;  // null = unchanged; "" = clear; data-URI = new logo
  window.ptBrandPickLogo = (input) => {
    const f = input.files && input.files[0];
    if (!f) return;
    if (f.size > 512 * 1024) { toast("Logo too large (max ~512 KB)", "err"); input.value = ""; return; }
    const r = new FileReader();
    r.onload = () => {
      _brandLogo = r.result;  // data:image/...;base64,...
      const p = document.getElementById("br-preview");
      if (p) p.innerHTML = `<img src="${esc(_brandLogo)}" style="height:48px">`;
    };
    r.readAsDataURL(f);
  };
  let _brandFav = null;  // null = unchanged
  window.ptBrandPickFavicon = (input) => {
    const f = input.files && input.files[0];
    if (!f) return;
    if (f.size > 512 * 1024) { toast("Favicon too large (max ~512 KB)", "err"); input.value = ""; return; }
    const r = new FileReader();
    r.onload = () => {
      _brandFav = r.result;
      const p = document.getElementById("br-fav-preview");
      if (p) p.innerHTML = `<img src="${esc(_brandFav)}" style="height:32px">`;
    };
    r.readAsDataURL(f);
  };
  window.ptClearLogo = () => {
    _brandLogo = "";
    const p = document.getElementById("br-preview");
    const emoji = document.getElementById("br-emoji").value || "🛡️";
    if (p) p.innerHTML = `<span style="font-size:40px">${esc(emoji)}</span>`;
    toast("Logo will be removed on save");
  };
  window.ptSaveBranding = async () => {
    const body = {
      app_name: document.getElementById("br-name").value.trim() || "ThreatProbe Scanner",
      logo_emoji: document.getElementById("br-emoji").value.trim() || "🛡️",
    };
    if (_brandLogo !== null) body.logo_data_url = _brandLogo;  // only send when changed
    if (_brandFav !== null) body.favicon_data_url = _brandFav;
    try {
      await API.put("/api/branding", body);
      _brandLogo = null; _brandFav = null;
      await ptApplyBranding();   // re-apply live (sidebar/title update immediately)
      toast("Branding saved");
      renderSettings();
    } catch (ex) { toast(ex.message, "err"); }
  };

  // ---------- Users ----------
  async function renderUsers() {
    view.innerHTML = pageHead("users", "Users",
      `<button class="btn btn-primary" onclick="ptNewUser()">+ Add user</button>`) + loading();
    try {
      const users = await API.get("/api/auth/users");
      const rows = users.map((u) => `
        <tr><td><b>${esc(u.username)}</b></td><td>${esc(u.role)}</td>
        <td>${u.is_active ? "active" : "disabled"}</td>
        <td><button class="btn btn-sm btn-danger" onclick="ptDelUser(${u.id})">Delete</button></td></tr>`).join("");
      view.innerHTML = pageHead("users", "Users",
        `<button class="btn btn-primary" onclick="ptNewUser()">+ Add user</button>`) + `
        <div class="table-wrap"><table>
        <thead><tr><th>Username</th><th>Role</th><th>Status</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    } catch (ex) { view.innerHTML = errBox(ex); }
  }
  window.ptNewUser = () => modal("Add user", `
    <div class="form-row"><label>Username</label><input id="u-name"></div>
    <div class="form-row"><label>Password</label><input id="u-pass" type="password"></div>
    <div class="form-row"><label>Role</label><select id="u-role">
      <option value="operator">operator</option><option value="admin">admin</option><option value="viewer">viewer</option>
    </select></div>
    <button class="btn btn-primary btn-block" onclick="ptSaveUser()">Create</button>`);
  window.ptSaveUser = async () => {
    try {
      await API.post("/api/auth/users", {
        username: document.getElementById("u-name").value.trim(),
        password: document.getElementById("u-pass").value,
        role: document.getElementById("u-role").value,
      });
      closeModal(); toast("User created"); renderUsers();
    } catch (ex) { toast(ex.message, "err"); }
  };
  window.ptDelUser = async (id) => {
    if (!confirm("Delete user?")) return;
    try { await API.del(`/api/auth/users/${id}`); toast("Deleted"); renderUsers(); }
    catch (ex) { toast(ex.message, "err"); }
  };

  const errBox = (ex) => `<div class="card" style="border-color:var(--high)">⚠️ ${esc(ex.message || ex)}</div>`;

  // ---------- About ----------
  async function renderAbout() {
    const name = (window._branding && window._branding.app_name) || "ThreatProbe Scanner";
    view.innerHTML = pageHead("about", "About") + loading();
    let stats = {};
    try { stats = await API.get("/api/dashboard/stats"); } catch {}
    const feat = (icon, title, body) =>
      `<div class="card about-feat"><div class="about-ic">${icon}</div><div><b>${title}</b><div class="muted small">${body}</div></div></div>`;
    const scanType = (name, body) => `<tr><td><b>${esc(name)}</b></td><td class="small">${body}</td></tr>`;
    view.innerHTML = pageHead("about", `About ${esc(name)}`) + `
      <div class="card about-hero">
        <div class="about-logo">${_logoHtml(window._branding || {}, 64)}</div>
        <div>
          <h2 style="margin:0 0 4px">${esc(name)}</h2>
          <p class="muted">Air-gapped Vulnerability Assessment &amp; Penetration-Testing platform — a self-contained, dependency-light security scanner you can run fully offline.</p>
          <div class="about-stats">
            <span><b>${(stats.cves || 0).toLocaleString()}</b> CVEs</span>
            <span><b>${stats.scans ?? 0}</b> scans</span>
            <span><b>${stats.targets ?? 0}</b> targets</span>
            <span><b>${stats.kev_findings ?? 0}</b> exploited (KEV)</span>
          </div>
        </div>
      </div>

      <h3 class="section-title">What it does</h3>
      <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px">
        ${feat("🌐", "Network &amp; server VA", "nmap discovery / port / version scans correlated against a local CVE database — no internet at scan time.")}
        ${feat("🕸️", "Web app testing (OWASP ZAP)", "Spider + passive + active scans, with authenticated (form/JSON/bearer) and AJAX/SPA crawling for deep coverage.")}
        ${feat("🔐", "Credentialed Linux audit", "SSH in, enumerate every package, map to CVEs with the exact fixed version — backport-aware via distro security feeds.")}
        ${feat("🛡️", "CIS benchmark / hardening", "Official CIS profiles via OpenSCAP (auto-installed) with L1/L2 Server/Workstation levels, plus a built-in agentless fallback.")}
        ${feat("🎯", "Risk prioritization", "CISA KEV (exploited-in-the-wild) flags + FIRST EPSS scores rank what to fix first — not just CVSS.")}
        ${feat("🗓️", "Scheduling &amp; reports", "Recurring scheduled scans, live scan logs, per-type PDF/CSV reports with charts, and emailed reports.")}
        ${feat("🤖", "Offline AI assistant", "A bundled local model (no internet) answers questions grounded on your own CVE DB and scan results — explains CVEs, summarises scans, teaches vuln classes.")}
        ${feat("⚙️", "Live tool-level settings", "Tune the engine from the GUI — scan flags, ZAP limits, severity floor, retention, session policy, target scope — no redeploy.")}
      </div>

      <h3 class="section-title">${icon("assistant")} Offline AI assistant</h3>
      <div class="card">
        <p>A built-in chat assistant powered by a <b>small quantized model running locally</b>
        (llama.cpp + a bundled GGUF) — it needs <b>no internet</b> and ships with the platform,
        so it works in fully air-gapped sites. Crucially, it's <b>RAG-grounded</b>: it never
        recalls facts from the model (which would hallucinate); instead the backend retrieves
        authoritative data from <b>this platform's own database</b> and the model explains only
        that. If the model is ever offline, it falls back to a deterministic database summary.</p>
        <div class="about-stats" style="margin-top:6px"><b>Use cases</b></div>
        <ul class="about-list" style="margin-top:8px">
          <li>💬 <b>Explain a CVE</b> — "explain CVE-2023-2975": severity, CVSS, KEV/EPSS risk, affected products, and the fix, from your local CVE DB.</li>
          <li>📊 <b>Summarise a scan</b> — "summarise scan #12": severity breakdown, top KEV/critical findings, web findings, failed CIS controls.</li>
          <li>📦 <b>Check a package</b> — backport-aware: which advisories affect a package and the distro-fixed version.</li>
          <li>🕸️ <b>Teach a vuln class</b> — XSS, SQLi, SSRF, CSRF, IDOR, weak TLS, missing CSP/HSTS… what it is and how to fix it.</li>
        </ul>
        <p class="muted small">Open it with the floating chat button (bottom-right). Admins can
        disable it in one click from the chat header, or toggle it under <b>Settings → AI Assistant</b>.</p>
      </div>

      <h3 class="section-title">Scan types</h3>
      <div class="table-wrap"><table class="fixed">
        <colgroup><col style="width:26%"><col style="width:74%"></colgroup>
        <thead><tr><th>Type</th><th>Description</th></tr></thead>
        <tbody>
          ${scanType("Server VA (nmap)", "Open ports + service/version detection, then CVE correlation.")}
          ${scanType("Host discovery / Port", "Ping sweep or open-port enumeration across IPs / CIDR pools.")}
          ${scanType("Web app (ZAP)", "Passive or active OWASP ZAP scan; optional authenticated + AJAX/SPA crawl.")}
          ${scanType("Credentialed Linux", "Authenticated package/CVE audit over SSH (backport-aware with distro feeds).")}
          ${scanType("CIS benchmark", "OpenSCAP CIS profile (L1/L2 Server/Workstation) or built-in hardening checks.")}
        </tbody></table></div>

      <h3 class="section-title">Built for the real world</h3>
      <div class="card">
        <ul class="about-list">
          <li>✅ Runs <b>100% offline / air-gapped</b> — one <code>docker compose up</code>; CVE feeds imported or exported between sites.</li>
          <li>✅ Served over <b>HTTPS</b> (self-signed by default); credentials are used <b>in-memory only and never stored</b>.</li>
          <li>✅ Role-based access (admin / operator / viewer), white-label branding, and stop-anytime scans.</li>
          <li>✅ Threat-intel enrichment (KEV + EPSS) and distro-accurate matching (RHEL/CentOS/Oracle/Rocky, Ubuntu/Debian).</li>
          <li>✅ <b>Offline AI assistant</b> grounded on local data, and a <b>tabbed Settings</b> page to tune the engine live (no redeploy).</li>
        </ul>
        <p class="muted small" style="margin-top:10px">⚠ For authorized security testing only. Scan only systems you own or have explicit written permission to assess.</p>
      </div>`;
  }

  // ---------- branding (white-label app name + logo) ----------
  // Modern default mark: a gradient shield (no flat emoji / white box). Used when no
  // custom logo image is uploaded and the emoji is the default.
  const BRAND_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    + '<defs><linearGradient id="tpg" x1="0" y1="0" x2="1" y2="1">'
    + '<stop offset="0" stop-color="#6366f1"/><stop offset=".5" stop-color="#8b5cf6"/>'
    + '<stop offset="1" stop-color="#d946ef"/></linearGradient></defs>'
    + '<path d="M32 3 7 12v17c0 15.5 10.4 24 25 30 14.6-6 25-14.5 25-30V12z" fill="url(#tpg)"/>'
    + '<path d="M21 32.5l7.5 7.5L44 24" fill="none" stroke="#fff" stroke-width="5.5" '
    + 'stroke-linecap="round" stroke-linejoin="round"/></svg>';
  const BRAND_URI = "data:image/svg+xml," + encodeURIComponent(BRAND_SVG);
  function _logoHtml(b, size) {
    if (b.logo_data_url)
      return `<img src="${esc(b.logo_data_url)}" alt="logo" style="height:${size}px;width:auto;vertical-align:middle;border-radius:8px">`;
    if (b.logo_emoji && b.logo_emoji !== "🛡️") return esc(b.logo_emoji);
    return `<img src="${BRAND_URI}" alt="logo" style="height:${size}px;width:auto;vertical-align:middle">`;
  }
  async function applyBranding() {
    try {
      const b = await API.get("/api/branding");
      const name = b.app_name || "ThreatProbe Scanner";
      document.title = name;
      const lt = document.getElementById("login-title"); if (lt) lt.textContent = name;
      const ll = document.getElementById("login-logo"); if (ll) ll.innerHTML = _logoHtml(b, 56);
      const br = document.getElementById("brand");
      if (br) br.innerHTML = `${_logoHtml(b, 24)} <span>${esc(name)}</span>`;
      // Favicon: custom favicon, else the uploaded logo, else the modern default shield —
      // so the browser tab always shows a crisp icon (never blank).
      const favUrl = b.favicon_data_url || b.logo_data_url || BRAND_URI;
      let link = document.querySelector("link[rel='icon']");
      if (!link) { link = document.createElement("link"); link.rel = "icon"; document.head.appendChild(link); }
      link.type = favUrl.includes("svg") ? "image/svg+xml" : "image/png";
      link.href = favUrl;
      window._branding = b;
    } catch { /* keep static defaults if branding can't load */ }
  }
  window.ptApplyBranding = applyBranding;

  // ---------- boot ----------
  applyBranding();
  if (API.token()) showApp(); else showLogin();
})();
