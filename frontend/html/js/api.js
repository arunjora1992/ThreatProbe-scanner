/* Lightweight API client with JWT handling. No external dependencies. */
const API = (() => {
  const TOKEN_KEY = "pt_token";
  const USER_KEY = "pt_user";

  function token() { return localStorage.getItem(TOKEN_KEY); }
  function setSession(data) {
    localStorage.setItem(TOKEN_KEY, data.access_token);
    localStorage.setItem(USER_KEY, JSON.stringify({ username: data.username, role: data.role }));
  }
  function user() {
    try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch { return null; }
  }
  function clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }

  async function request(path, options = {}) {
    const headers = options.headers || {};
    if (token()) headers["Authorization"] = "Bearer " + token();
    if (options.body && !(options.body instanceof FormData) && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    const res = await fetch(path, { ...options, headers });
    if (res.status === 401) {
      clear();
      window.dispatchEvent(new Event("pt-unauthorized"));
      throw new Error("Unauthorized");
    }
    if (!res.ok) {
      let detail = res.statusText;
      try { detail = (await res.json()).detail || detail; } catch {}
      throw new Error(detail);
    }
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res.text();
  }

  async function login(username, password) {
    const body = new URLSearchParams({ username, password });
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) {
      let d = "Login failed";
      try { d = (await res.json()).detail || d; } catch {}
      throw new Error(d);
    }
    const data = await res.json();
    setSession(data);
    return data;
  }

  return {
    token, user, clear, login,
    get: (p) => request(p),
    post: (p, body) => request(p, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
    patch: (p, body) => request(p, { method: "PATCH", body: JSON.stringify(body) }),
    put: (p, body) => request(p, { method: "PUT", body: JSON.stringify(body) }),
    del: (p) => request(p, { method: "DELETE" }),
    // download a file (uses token via query-less fetch then blob)
    download: async (path, filename) => {
      const res = await fetch(path, { headers: { Authorization: "Bearer " + token() } });
      if (!res.ok) throw new Error("Download failed");
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename; document.body.appendChild(a); a.click();
      a.remove(); URL.revokeObjectURL(url);
    },
  };
})();
