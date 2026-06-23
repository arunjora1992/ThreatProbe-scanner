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
    navigateFromUrl();
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

  // ---------- routing (path-based, reflected in the browser URL) ----------
  const ROUTES = { dashboard: renderDashboard, targets: renderTargets, scans: renderScans,
                   cves: renderCves, reports: renderReports, settings: renderSettings,
                   users: renderUsers };

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
    view.innerHTML = `<div class="page-head"><h1>Dashboard</h1></div>` + loading();
    try {
      const s = await API.get("/api/dashboard/stats");
      const sev = s.severity_breakdown || {};
      const sevColors = { CRITICAL: "var(--crit)", HIGH: "var(--high)", MEDIUM: "var(--med)", LOW: "var(--low)", INFO: "var(--info)", NONE: "var(--info)", UNKNOWN: "var(--info)" };
      const sevTotal = Object.values(sev).reduce((a, b) => a + b, 0) || 1;
      const bar = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
        .filter((k) => sev[k])
        .map((k) => `<div style="background:${sevColors[k]};flex:${sev[k]}" title="${k}: ${sev[k]}">${sev[k]}</div>`)
        .join("") || `<div style="background:var(--info);flex:1">No findings yet</div>`;

      const cards = [
        ["Targets", s.targets], ["Scans", s.scans], ["Hosts discovered", s.hosts],
        ["CVEs in DB", s.cves], ["Total findings", s.findings_total],
      ].map(([l, n]) => `<div class="card stat-card"><div class="stat-num">${n}</div><div class="stat-label">${l}</div></div>`).join("");

      const recent = (s.recent_scans || []).map((sc) => `
        <tr onclick="ptOpenScan(${sc.id})" style="cursor:pointer">
          <td>#${sc.id}</td><td>${esc(sc.scan_type)}</td>
          <td>${statusBadge(sc.status)}</td><td>${sc.finding_count}</td>
          <td>${fmtDate(sc.created_at)}</td></tr>`).join("") ||
        `<tr><td colspan="5" class="empty">No scans yet</td></tr>`;

      view.innerHTML = `
        <div class="page-head"><h1>Dashboard</h1></div>
        <div class="grid stat-grid">${cards}</div>
        <h3 class="section-title">Severity breakdown (all findings)</h3>
        <div class="sev-bar">${bar}</div>
        <h3 class="section-title">Recent scans</h3>
        <div class="table-wrap"><table>
          <thead><tr><th>Scan</th><th>Type</th><th>Status</th><th>Findings</th><th>Created</th></tr></thead>
          <tbody>${recent}</tbody></table></div>`;
    } catch (ex) { view.innerHTML = errBox(ex); }
  }

  // ---------- Targets ----------
  async function renderTargets() {
    view.innerHTML = `<div class="page-head"><h1>Targets</h1>
      <button class="btn btn-primary" onclick="ptNewTarget()">+ Add target</button></div>` + loading();
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
      view.innerHTML = `<div class="page-head"><h1>Targets</h1>
        <button class="btn btn-primary" onclick="ptNewTarget()">+ Add target</button></div>
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
  window.ptScanTarget = (id, name, address) => {
    modal(`Launch scan — ${esc(name)}`, `
      <p class="muted small">Target: <code>${esc(address)}</code></p>
      <div class="form-row"><label>Scan type</label>
        <select id="s-type" onchange="ptToggleScanFields()">
          <option value="full">Server vulnerability assessment (nmap -sV + CVE)</option>
          <option value="credentialed">Credentialed Linux assessment (SSH package audit)</option>
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
  };
  window.ptToggleScanFields = () => {
    const v = document.getElementById("s-type").value;
    document.getElementById("s-custom-row").classList.toggle("hidden", v !== "custom");
    document.getElementById("s-cred-rows").classList.toggle("hidden", v !== "credentialed");
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
    if (scan_type === "credentialed") {
      body.ssh_username = document.getElementById("s-user").value.trim();
      body.ssh_password = document.getElementById("s-pass").value || null;
      body.ssh_key = document.getElementById("s-key").value.trim() || null;
      body.ssh_key_passphrase = document.getElementById("s-keypass").value || null;
      body.ssh_port = parseInt(document.getElementById("s-port").value, 10) || 22;
      if (!body.ssh_username || (!body.ssh_password && !body.ssh_key)) {
        toast("Username and a password or private key are required", "err"); return;
      }
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
    view.innerHTML = `<div class="page-head"><h1>Scans</h1>
      <span class="muted small">Auto-refreshing</span></div>
      <div class="table-wrap"><table>
      <thead><tr><th>Scan</th><th>Target</th><th>Type</th><th>Status</th><th>By</th><th>Created</th><th></th></tr></thead>
      <tbody id="scans-tbody"><tr><td colspan="7">${loading()}</td></tr></tbody></table></div>`;
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
          <td>${esc(s.created_by)}</td>
          <td>${fmtDate(s.created_at)}</td>
          <td onclick="event.stopPropagation()" class="pill-row">
            <button class="btn btn-sm" onclick="ptOpenScan(${s.id})">View</button>
            <button class="btn btn-sm btn-danger" onclick="ptDelScan(${s.id})">Del</button>
          </td></tr>`;
      }).join("") || `<tr><td colspan="7" class="empty">No scans yet. Launch one from Targets.</td></tr>`;
      tbody.innerHTML = rows;
    } catch (ex) { stopPolling(); tbody.innerHTML = `<tr><td colspan="7">${errBox(ex)}</td></tr>`; }
  }
  window.ptDelScan = async (id) => {
    if (!confirm("Delete scan #" + id + "?")) return;
    try { await API.del(`/api/scans/${id}`); toast("Deleted"); refreshScans(); }
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
      const showHosts = Array.isArray(scan.hosts) && scan.hosts.length > 0
        && scan.scan_type !== "credentialed";
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

      view.innerHTML = `
        <div class="page-head">
          <h1>Scan #${scan.id} <span class="muted" style="font-size:14px">${esc(scan.scan_type)}</span></h1>
          <div class="pill-row">
            <button class="btn" onclick="route('scans')">← Back</button>
            <button class="btn btn-primary" onclick="ptDownload(${scan.id},'pdf')">⬇ PDF report</button>
            <button class="btn btn-primary" onclick="ptDownload(${scan.id},'csv')">⬇ CSV report</button>
            ${scan.scan_type === "credentialed" ? `<button class="btn" onclick="ptDownloadPkgs(${scan.id})">⬇ Package inventory CSV</button>` : ""}
            <button class="btn" onclick="ptEmailScan(${scan.id})">✉ Email report</button>
          </div>
        </div>
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
        <h3 class="section-title">Live scan log <span id="log-live"></span></h3>
        <pre id="scan-console" class="console"></pre>
        ${showHosts ? `
        <h3 class="section-title">Discovered hosts &amp; open ports (${scan.hosts.length} host${scan.hosts.length === 1 ? "" : "s"}${scan.scan_type !== "discovery" ? `, ${openPortCount} open port${openPortCount === 1 ? "" : "s"}` : ""})</h3>
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:26%"><col style="width:13%"><col style="width:10%"><col style="width:19%"><col style="width:32%"></colgroup>
          <thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Product / version</th></tr></thead>
          <tbody>${hostRows || `<tr><td colspan="5" class="empty">No hosts up.</td></tr>`}</tbody></table></div>` : ""}
        <h3 class="section-title">CVE findings (${findings.length})</h3>
        ${findings.length > FIND_CAP ? `<p class="muted small">Showing first ${FIND_CAP}. Use the Reports page or CSV export for the full set.</p>` : ""}
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:15%"><col style="width:13%"><col style="width:9%"><col style="width:6%"><col style="width:6%"><col style="width:36%"><col style="width:15%"></colgroup>
          <thead><tr><th>CVE</th><th>Package / service</th><th>Severity</th><th>CVSS</th><th title="EPSS: probability of exploitation in next 30 days">EPSS</th><th>Match / fix</th><th>Status</th></tr></thead>
          <tbody>${findRows}</tbody></table></div>
        <h3 class="section-title">Web / URL findings (${webFindings.length})</h3>
        <div class="table-wrap"><table class="fixed">
          <colgroup><col style="width:40%"><col style="width:14%"><col style="width:10%"><col style="width:36%"></colgroup>
          <thead><tr><th>Finding</th><th>Category</th><th>Severity</th><th>Remediation</th></tr></thead>
          <tbody>${webRows}</tbody></table></div>
        ${scan.scan_type === "credentialed" ? `
        <div class="page-head" style="margin-top:22px;margin-bottom:8px">
          <h3 class="section-title" style="margin:0">Installed package inventory</h3>
          <label class="muted small"><input type="checkbox" id="pkg-vuln-only" style="width:auto" onchange="ptLoadPackages(${scan.id})"> show vulnerable only</label>
        </div>
        <input id="pkg-q" placeholder="Filter packages by name…" style="margin-bottom:8px" oninput="ptDebouncePkgs(${scan.id})">
        <div id="pkg-box">${loading()}</div>` : ""}`;

      if (scan.scan_type === "credentialed") ptLoadPackages(scan.id);

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
    view.innerHTML = `<div class="page-head"><h1>CVE Database</h1>
      <div class="pill-row">
        <button class="btn" onclick="ptExportCveDb()">⬇ Download CVE DB</button>
        <button class="btn admin-only" onclick="document.getElementById('cve-upload-file').click()">⬆ Upload CVE DB</button>
        <button class="btn btn-primary admin-only" onclick="ptImportFeeds()">⬆ Import NVD feeds</button>
        <button class="btn admin-only" onclick="ptImportThreatIntel()" title="Enrich CVEs with CISA KEV (exploited-in-the-wild) + FIRST EPSS scores">🎯 Import KEV / EPSS</button>
        <input type="file" id="cve-upload-file" accept=".json,.gz,.json.gz,.json.xz" style="display:none" onchange="ptUploadCveDb(this)">
      </div></div>`
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
  window.ptImportThreatIntel = async () => {
    toast("Importing KEV + EPSS from /data/cve_feeds … enriching existing CVEs");
    try {
      const r = await API.post("/api/cves/threat-intel/import");
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
    view.innerHTML = `<div class="page-head"><h1>Reports</h1></div>` + loading();
    let targets = [];
    try { targets = await API.get("/api/targets"); } catch (ex) { view.innerHTML = errBox(ex); return; }
    const targetOpts = `<option value="">All scans / all targets</option>` +
      targets.map((t) => `<option value="${t.id}">${esc(t.name)} (${esc(t.address)})</option>`).join("");
    view.innerHTML = `
      <div class="page-head"><h1>Reports</h1>
        <span class="muted small">Build a consolidated, filtered report across scans</span></div>
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
  async function renderSettings() {
    view.innerHTML = `<div class="page-head"><h1>Email / SMTP Settings</h1></div>` + loading();
    try {
      const c = await API.get("/api/settings/smtp");
      view.innerHTML = `
        <div class="page-head"><h1>Email / SMTP Settings</h1></div>
        <div class="card" style="max-width:620px">
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
    } catch (ex) { view.innerHTML = errBox(ex); }
  }
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

  // ---------- Users ----------
  async function renderUsers() {
    view.innerHTML = `<div class="page-head"><h1>Users</h1>
      <button class="btn btn-primary" onclick="ptNewUser()">+ Add user</button></div>` + loading();
    try {
      const users = await API.get("/api/auth/users");
      const rows = users.map((u) => `
        <tr><td><b>${esc(u.username)}</b></td><td>${esc(u.role)}</td>
        <td>${u.is_active ? "active" : "disabled"}</td>
        <td><button class="btn btn-sm btn-danger" onclick="ptDelUser(${u.id})">Delete</button></td></tr>`).join("");
      view.innerHTML = `<div class="page-head"><h1>Users</h1>
        <button class="btn btn-primary" onclick="ptNewUser()">+ Add user</button></div>
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

  // ---------- boot ----------
  if (API.token()) showApp(); else showLogin();
})();
