<p align="center">
  <img src="docs/logo.svg" alt="ThreatProbe Scanner" width="104" height="104" />
</p>

<h1 align="center">ThreatProbe Scanner</h1>

<p align="center">
  <b>Air-Gapped Vulnerability Assessment &amp; Penetration Testing Platform</b><br/>
  <sub>Network &amp; server VA · Web/ZAP testing · Credentialed audits · CIS hardening · KEV/EPSS risk · Offline AI assistant</sub>
</p>

<p align="center">
  <img alt="Deployment: air-gapped" src="https://img.shields.io/badge/deployment-air--gapped-4f46e5" />
  <img alt="Run with Docker Compose" src="https://img.shields.io/badge/run-Docker%20Compose-2496ed?logo=docker&logoColor=white" />
  <img alt="Backend: FastAPI / Python" src="https://img.shields.io/badge/backend-FastAPI%20%C2%B7%20Python-009688?logo=fastapi&logoColor=white" />
  <img alt="Database: PostgreSQL" src="https://img.shields.io/badge/db-PostgreSQL-316192?logo=postgresql&logoColor=white" />
  <img alt="Web scanner: OWASP ZAP" src="https://img.shields.io/badge/web-OWASP%20ZAP-00549e" />
  <img alt="Offline AI: llama.cpp" src="https://img.shields.io/badge/AI-offline%20%C2%B7%20llama.cpp-8b5cf6" />
  <img alt="Data: NVD · KEV · EPSS · OVAL" src="https://img.shields.io/badge/feeds-NVD%20%C2%B7%20KEV%20%C2%B7%20EPSS%20%C2%B7%20OVAL-be123c" />
</p>

A self-contained, **Docker-Compose based** vulnerability assessment and penetration
testing platform built to run **fully offline / air-gapped**. It provides a web GUI,
a local CVE database, network/server vulnerability scanning, URL/web-application
penetration testing, persistent storage of every scan, and **CSV/PDF report export**
with vulnerability, severity, CVSS, and remediation details.

---

## Table of contents

1. [Key capabilities](#key-capabilities)
2. [Architecture](#architecture)
3. [Technology stack](#technology-stack)
4. [Project layout](#project-layout)
5. [Prerequisites](#prerequisites)
6. [Quick start](#quick-start)
7. [Default credentials & ports](#default-credentials--ports)
8. [Using the platform](#using-the-platform)
9. [Scan types](#scan-types)
10. [Web / URL penetration test checks](#web--url-penetration-test-checks)
11. [Server vulnerability assessment & CVE correlation](#server-vulnerability-assessment--cve-correlation)
12. [The local CVE database (offline import)](#the-local-cve-database-offline-import)
13. [Reports (CSV / PDF)](#reports-csv--pdf)
14. [Roles & permissions](#roles--permissions)
15. [Data model](#data-model)
16. [REST API reference](#rest-api-reference)
17. [Configuration (environment variables)](#configuration-environment-variables)
18. [Air-gapped deployment](#air-gapped-deployment)
19. [Backup & restore](#backup--restore)
20. [Troubleshooting](#troubleshooting)
21. [Feature changelog](#feature-changelog)
22. [Bug history & fixes](#bug-history--fixes)
23. [Authorization & scope](#authorization--scope)

---

## Key capabilities

- **Web GUI** — a dependency-free single-page application (plain HTML/CSS/JS, **no CDN,
  no npm build step**) served by nginx. Works in a browser with zero internet access.
- **Local CVE database** — stored in PostgreSQL, populated from **NVD JSON feeds**
  imported offline. Ships pre-seeded with well-known sample CVEs so it is useful
  immediately.
- **Network / server vulnerability assessment** — `nmap` host discovery, port
  scanning, and service/version detection, with **automatic correlation** of
  discovered services against the local CVE database.
- **URL / web-application penetration testing** — non-destructive checks for security
  headers, TLS/certificate issues, software fingerprinting (+ CVE lookup), cookie
  flags, dangerous HTTP methods, sensitive-path exposure, and reflected-input
  indicators.
- **Persistent storage** — every target, scan, discovered host, open service, and
  finding is stored and browsable.
- **Reporting** — export any scan as **CSV** or a styled **PDF** report containing the
  vulnerability, severity, CVSS score/vector, description, **remediation**, and
  references.
- **Authentication & roles** — JWT login with `admin`, `operator`, and `viewer` roles.
- **Multi-host targets** — a single target may list several IPs/hostnames/CIDRs (space, comma, or newline separated); all are scanned together.
- **Live scan log** — a shell-like, auto-scrolling terminal view per scan, streaming progress in real time (nmap output, ZAP spider/active stages, per-host SSH package correlation).
- **Email reports** — SMTP is configured **in the GUI** (stored in the DB, not in files); email any scan's report with the severity summary in the body and PDF/CSV attached.
- **Scheduled CVE updates** — opt-in auto-refresh of the CVE database every N hours (default 24), online from the NVD mirror or by re-importing the offline feed directory; controlled from the CVE Database page.
- **Scheduled scans** — define **recurring scans** per target (every N hours) from the **Schedules** page; the backend auto-runs them. Credential-less scan types only (SSH/CIS need in-memory credentials that are never stored).
- **Stop / cancel scans** — halt a running or queued scan from the GUI; the worker (nmap) and backend threads abort cooperatively and the scan is marked `cancelled`.
- **Rescan** — one click on any scan re-runs the same scan type against the same target (re-prompting for SSH/web credentials, which are never stored).
- **Risk prioritization (KEV + EPSS)** — findings and the CVE browser are ranked by **CISA KEV** (actively-exploited) then **FIRST EPSS** likelihood, not just CVSS — so the riskiest items surface first (see below).
- **CIS benchmark / hardening** — authenticated CIS audits via **OpenSCAP** (auto-installed on the target when missing) with selectable **Level 1/2 Server/Workstation** profiles, plus a built-in agentless fallback (see below).
- **Modern dashboard** — severity donut, scan-status chart, and a **Top priorities** panel (exploited / high-risk findings).
- **Vibrant UI** — indigo/violet gradient theme with a consistent inline-SVG icon set per page (no external assets — air-gap safe), icon-led KPI cards, and brand-matched **PDF reports** (indigo header band, cyan accent, colour-coded severity).
- **Live tool-level settings** — a tabbed Settings page exposes engine knobs with no `.env` edit or rebuild: nmap flags / SYN scan / scan timeout, ZAP crawl & active-scan limits, minimum severity shown, default CVE sort, scan auto-retention, session lifetime, password policy, and a **target scope allowlist** (CIDR/host globs that scans must match). Stored in the DB, read at runtime, with per-section *reset to defaults*.
- **Offline AI assistant** — a built-in chat widget backed by a small local model (llama.cpp + a bundled quantized GGUF, **no internet**). It can **launch scans conversationally** (guided wizard: target → type → credentials → confirm → auto-summary on completion) and answer questions **RAG-grounded** on this platform's own CVE DB / scan findings / package feeds — explains CVEs, summarises a scan, checks a package, teaches vuln classes (XSS/SQLi/SSRF…) **without inventing facts**. Credentials entered in chat are masked, in-memory only, and never stored/sent to the model. Degrades gracefully to a deterministic DB summary if the model is offline (see below).
- **White-label branding** — set a custom **application name, logo, and favicon** (emoji or an uploaded PNG/SVG) from **Settings → Branding**; applied to the login page, sidebar, and browser tab. An in-app **About** page describes the tool.
- **Dark / light theme** toggle (persisted per browser).

---

## Architecture

```
                       ┌───────────────────────┐
        Browser  ─HTTPS▶│  frontend (nginx)     │  :8443 (TLS) / :8080→redirect
                       │  static GUI + /api ───┐│
                       └───────────────────────┘│
                                                ▼
                       ┌───────────────────────┐
                       │  backend (FastAPI)    │  :8000  REST API, auth, reports
                       └───────────┬───────────┘
                                   │ shared PostgreSQL
                       ┌───────────▼───────────┐
                       │  db (PostgreSQL 16)   │  :5432  CVEs, scans, findings
                       └───────────▲───────────┘
                                   │ polls for queued scans
                       ┌───────────┴───────────┐
                       │  worker (nmap + web)  │  executes scans
                       └───────────────────────┘
```

| Service    | Image                | Role                                                    |
|------------|----------------------|---------------------------------------------------------|
| `db`       | `postgres:16-alpine` | Stores CVEs, targets, scans, hosts, services, findings  |
| `backend`  | `python:3.12-slim`   | FastAPI REST API: auth, targets, scans, CVE, reports    |
| `worker`   | `python:3.12` + nmap | Polls the DB and runs scans (nmap / built-in web / ZAP / SSH) |
| `zap`      | `zaproxy/zaproxy`    | OWASP ZAP daemon — web-application scanning engine (REST API) |
| `frontend` | `nginx:1.27-alpine`  | Serves the GUI and reverse-proxies `/api` to backend    |

**Why no Redis/Celery?** A database-backed job queue (the worker polls for `queued`
scans and claims them with `SELECT … FOR UPDATE SKIP LOCKED`) keeps the number of
services — and therefore the air-gapped image set — to a minimum, while still allowing
multiple workers to run safely.

---

## Technology stack

- **Backend:** Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2, python-jose (JWT),
  passlib/bcrypt.
- **Scanning:** `nmap` (network/server), Python standard library (`urllib`, `ssl`)
  for web checks — **no third-party scanning dependencies**, so it works offline.
- **Reports:** `reportlab` (pure-Python PDF, no system libraries) and the stdlib `csv`.
- **Database:** PostgreSQL 16.
- **Frontend:** vanilla HTML/CSS/JavaScript (no framework, no build tooling).
- **Orchestration:** Docker Compose.

---

## Project layout

```
pentest-platform/
├── docker-compose.yml          # 4 services: db, backend, worker, frontend
├── .env.example                # copy to .env and set secrets
├── README.md
├── data/
│   └── cve_feeds/              # drop NVD JSON feeds here for offline import
├── backend/
│   ├── Dockerfile              # python:3.12-slim + nmap
│   ├── requirements.txt
│   └── app/
│       ├── main.py             # FastAPI app, startup, DB wait, seeding
│       ├── config.py           # env-driven settings
│       ├── database.py         # SQLAlchemy engine/session
│       ├── models.py           # ORM models (schema)
│       ├── schemas.py          # Pydantic request/response models
│       ├── auth.py             # password hashing, JWT, role guards
│       ├── seed.py             # bootstrap admin + sample CVEs
│       ├── worker.py           # background scan runner
│       ├── routers/            # auth, targets, scans, cves, findings, reports, dashboard
│       └── services/
│           ├── scanner.py      # nmap wrapper + XML parser
│           ├── cve_matcher.py  # service → CVE correlation
│           ├── cve_import.py   # NVD 1.1 / 2.0 feed importer
│           ├── web_scanner.py  # URL / web-app checks
│           ├── report_csv.py   # CSV export
│           └── report_pdf.py   # PDF export (reportlab)
└── frontend/
    ├── Dockerfile              # nginx + static assets
    ├── nginx.conf              # serves GUI, proxies /api → backend
    └── html/
        ├── index.html
        ├── css/styles.css
        └── js/{api.js,app.js}
```

---

## Prerequisites

- Docker Engine 24+ and Docker Compose v2.
- ~2 GB free disk for images + database volume.
- For real network scans, the `worker` container needs network reachability to the
  targets. The compose file grants `NET_RAW`/`NET_ADMIN` so faster `-sS` scans are
  possible; the default profiles use TCP connect scans that work without them.

---

## Quick start

```bash
cp .env.example .env          # then edit secrets/passwords
docker compose up -d --build
```

Wait ~15 seconds for the database to become healthy and the backend to seed, then open:

> **https://localhost:8443**

The GUI is served over **HTTPS with a self-signed certificate** (generated automatically
on first start), so your browser will show a one-time "not secure / untrusted certificate"
warning — accept it to proceed. Plain `http://localhost:8080` automatically redirects to
HTTPS. Log in with the admin credentials from your `.env`.

To watch startup:

```bash
docker compose logs -f backend     # look for "[api] startup complete"
docker compose logs -f worker      # "[worker] started; ... nmap=available"
```

---

## Default credentials & ports

| Item            | Default                                   | Where to change        |
|-----------------|-------------------------------------------|------------------------|
| Admin username  | `admin`                                   | `ADMIN_USERNAME` (.env)|
| Admin password  | value of `ADMIN_PASSWORD` in `.env`       | `ADMIN_PASSWORD` (.env)|
| GUI URL (HTTPS) | `https://localhost:8443` (self-signed)    | `FRONTEND_HTTPS_PORT` (.env) |
| GUI URL (HTTP)  | `http://localhost:8080` → redirects to HTTPS | `FRONTEND_PORT` (.env) |
| API (internal)  | `backend:8000` (proxied via `/api`)       | —                      |
| Database        | `db:5432` (not published to host)         | —                      |

> ⚠️ The admin account is created **only on first startup** (when the users table is
> empty). Change `SECRET_KEY`, `ADMIN_PASSWORD`, and `POSTGRES_PASSWORD` **before**
> first launch in any real deployment. To reset, drop the `pgdata` volume (see
> [Backup & restore](#backup--restore)).

---

## Using the platform

1. **Add a target** — *Targets → + Add target*. Enter:
   - an **IP**, **hostname**, or **CIDR range** (e.g. `10.0.0.5`, `10.0.0.0/24`) for
     network/server scans, or
   - a **URL** (e.g. `https://app.internal`) for web/URL penetration tests.
2. **Launch a scan** — click **Scan** on a target and pick a [scan type](#scan-types).
3. **Monitor** — the *Scans* page auto-refreshes every 4 seconds and shows
   `queued → running → completed/failed` with a progress percentage.
4. **Review** — open a scan to see discovered hosts and services, correlated **CVE
   findings**, and **web findings**. Triage each CVE finding's status
   (`open / confirmed / false_positive / fixed / accepted`).
5. **Export** — download a **PDF** or **CSV** report from the scan detail page.
6. **Browse CVEs** — the *CVE Database* page lets you search by ID, description, or
   product and filter by severity. Admins can import NVD feeds here.
7. **Manage users** (admin) — create operator/viewer/admin accounts under *Users*.

---

## Scan types

| Type                                | nmap flags (default)      | Purpose |
|-------------------------------------|---------------------------|---------|
| **Server vulnerability assessment** (`full`) | `-sT -sV -T4 --open` | Open ports + service/version detection, then CVE correlation. Unauthenticated/remote. |
| **Credentialed Linux assessment** (`credentialed`) | _SSH_ | Authenticated scan: logs in over SSH, enumerates **all installed packages + versions**, and reports each package's CVEs, criticality, and the **version to upgrade to**. Credentials are used in-memory only and never stored. |
| **CIS benchmark / hardening audit** (`cis_benchmark`) | _SSH_ | Authenticated, **agentless** host-hardening audit: official CIS profile via OpenSCAP when present, else built-in read-only checks. Reports failed controls + remediation (+ compliance score with OpenSCAP). Credentials in-memory only. |
| **Host discovery** (`discovery`)    | `-sn`                     | Ping sweep — which hosts in a range are up. |
| **Port scan** (`port`)              | `-sT -T4 --open`          | Open ports only (no version detection). |
| **Web / URL penetration test** (`web`) | _n/a_                  | Built-in lightweight, non-destructive checks against the target URL (see below), incl. precise software→CVE correlation. |
| **Web app scan — ZAP passive** (`zap_passive`) | _OWASP ZAP_ | Spider/crawl + passive analysis via OWASP ZAP. Non-destructive (no attack payloads). Many more findings than the built-in scanner. Optionally **authenticated** (cookie or bearer-token login) and **AJAX-spidered** (JS/SPA crawling) for deeper coverage. |
| **Web app scan — ZAP active** (`zap_active`) | _OWASP ZAP_ | Spider then **active** attack (XSS, SQLi, injection, traversal…). **Intrusive — authorized targets only.** Optionally **authenticated** (cookie or bearer-token login) and **AJAX-spidered** (JS/SPA crawling) for deeper coverage. |
| **Custom** (`custom`)               | operator-supplied         | Any nmap flags you provide, e.g. `-sT -sV -p 1-1000 --script vuln`. |

### Web application scanning — built-in vs OWASP ZAP

There are two web engines:

- **Built-in** (`web`) — a fast, dependency-free, **non-destructive** passive checker
  (security headers, TLS, cookies, methods, sensitive-path probe with SPA catch-all
  guard, reflected-input canary, software→CVE). Surfaces misconfigurations, not
  exploitable web-app vulns.
- **OWASP ZAP** (`zap_passive` / `zap_active`) — the integrated industry-standard web
  scanner, run as a headless daemon (`zap` service) and driven via its REST API. Passive
  mode crawls + analyzes; **active** mode sends real attack payloads to find XSS/SQLi/
  injection/traversal. ZAP alerts are de-duplicated per alert-type and stored as web
  findings (severity, description, evidence, **solution/remediation**, references, CWE).

> ZAP **active** scanning is intrusive (it attacks the target) — only run it against
> systems you are explicitly authorized to actively test. ZAP also needs memory
> (capped at 2 GB in compose) and writes session data; on a disk-constrained host keep
> active scans scoped. The ZAP session is reset at the start of each scan to bound disk
> use.

#### Authenticated ZAP scans (deeper coverage)

Both `zap_passive` and `zap_active` can run **as a logged-in user**. Unauthenticated
scans only see public pages, so they miss the bulk of an application's attack surface;
supplying a login lets ZAP crawl and attack the pages behind authentication, which is
where most real vulnerabilities are. In the launch dialog, expand the **Authenticated
scan** section and provide:

- **Auth type** — `form` (HTML login form), `json` (SPA/API login endpoint), or
  `http` (HTTP Basic / NTLM).
- **Username / password**, and (for form/json) the **login URL** the credentials are
  POSTed to plus the **field names** for the username and password.
- **Session handling** — how the app keeps you logged in:
  - **Cookie session** (default) — traditional server-rendered apps that set a session
    cookie.
  - **Bearer token in header** — SPAs / APIs that return a token in the login JSON and
    replay it as `Authorization: Bearer <token>`. Give the **token field** in the login
    response (e.g. `token`, `access_token`, `data.token`) and ZAP extracts it
    (`{%json:<field>%}`) and re-sends it on every request. Without this, a token-based
    login "succeeds" but the session is immediately lost and the scan stays shallow.
- *(Optional)* **extra login params** (e.g. a CSRF token / submit button), and
  **logged-in / logged-out indicator** regexes so ZAP can detect session expiry and
  re-authenticate mid-scan (e.g. logged-in `\bLogout\b`).

Under the hood the platform creates a ZAP context, configures the chosen authentication
and session-management methods, registers a user with the supplied credentials, and runs
the spider + active scan **as that user** (`scanAsUser`). Leaving the username blank runs
the normal anonymous scan.

Like credentialed Linux scans, **authenticated ZAP scans run inside the backend** (not
the DB worker) so the login credentials are held **in memory only and never written to
the database or logs**; they start immediately rather than queueing.

#### AJAX spider (JavaScript / SPA crawling)

The traditional spider only parses static HTML, so it can't see the routes or API calls
of a JavaScript app (Angular / React / Vue) — it finds the page shell and little else.
Tick **Use AJAX spider** in the launch dialog to run ZAP's browser-driven crawl
(headless Firefox, bundled in the ZAP image) after the normal spider; it executes the
app's JavaScript to discover client-side routes and the API endpoints behind them. It
works with or without authentication, and obeys the same scope bounds.

> The AJAX spider launches a real browser, so it is heavier. The platform pins it to a
> **single browser instance** (ZAP otherwise defaults to one per CPU core, which
> exhausts memory and crashes the daemon), and the `zap` service is given a larger
> `/dev/shm` and a relaxed seccomp profile in `docker-compose.yml` so the browser runs
> stably in a container. Crawl duration, depth, state count and browser count are tunable
> via the `ZAP_AJAX_*` settings.

### Credentialed Linux assessment (authenticated package VA)

This is the most accurate "server VA". When launching a scan, choose **Credentialed
Linux assessment** and supply an SSH username + password (or private key) and port.
The platform:

1. Connects over SSH (credentials held in memory only, **never written to the DB or logs**).
2. Enumerates the **full installed-package inventory** (`dpkg` or `rpm`) and OS/kernel.
3. Matches every package version against the local CVE database using precise,
   version-range matching, and records each vulnerable package's CVEs, **criticality**,
   and the **fixed version to upgrade to**.

The full inventory (every package, vulnerable or not) is stored and downloadable as a
dedicated **Package inventory CSV** from the scan detail page. Because credentialed
scans run inside the backend (so credentials need never be persisted for a DB worker),
they start immediately rather than queueing.

### CIS benchmark / hardening audit (`cis_benchmark`)

A **separate** authenticated scan type (not bundled into the package audit) that assesses
**host hardening / misconfiguration** — weaknesses no CVE feed will ever surface. It uses
the same in-memory SSH credentials and is **agentless**: it installs nothing on the target.

Two engines, auto-selected:

- **OpenSCAP** — runs the **official CIS profile** and imports every rule (CIS rule id,
  severity, pass/fail, remediation) plus a **compliance score**. If `oscap` + SCAP
  Security Guide aren't present, the scan **auto-installs** them on the target
  (`dnf`/`yum`/`apt`/`zypper`); if that fails (no root or no package mirror) it falls back
  to the built-in checks. You choose the **profile/level** in the launch dialog — **Level 1
  / Level 2**, **Server / Workstation** — and on RHEL clones (CentOS Stream / Rocky / Alma)
  the matching SSG datastream is preferred so rules aren't all marked *notapplicable*.
- **Built-in agentless checks (default fallback)** — when OpenSCAP isn't available, a set
  of read-only checks run from the scanner over SSH (reading configs, sysctls, perms):
  SSH config (root login, password/empty-password auth, X11), password policy
  (`PASS_MAX_DAYS`, pwquality minlen), UMASK, UID-0 accounts, ASLR, IP forwarding, SUID
  core dumps, host firewall, auditd, system logging, legacy services (telnet/rsh/tftp),
  unneeded filesystem modules, world-writable files/dirs, cron permissions, and more.

Results appear in a **CIS benchmark / hardening results** section on the scan detail page,
led by a summary banner showing the **distro assessed, the benchmark level (e.g. CIS Level 1
Server), the engine, and the compliance score**, then failures ranked by severity. The same
distro + level + engine + score appear in the PDF report. All checks are
**read-only** and best-effort: one that can't run (e.g. `/etc/shadow` needs more privilege
than the scan account has) is reported as *n/a* rather than a false pass/fail — so prefer a
scan account with adequate `sudo`/read access for full coverage.

### Distro security feeds (backport-aware matching)

Distros **backport** security fixes onto a base package version (RHEL ships
`kernel-5.14.0-427.el9`, not the upstream version the fix first appeared in), so matching
the upstream version against NVD ranges **over-reports** — it flags CVEs your distro has
already patched. To fix this, load **vendor security advisories** and the credentialed
package audit will use the distro's *fixed version* instead of NVD.

Supported, air-gap-friendly feeds — drop them in **`data/cve_feeds/distro_feeds/`** then
**CVE Database → 🐧 Import distro feeds** (or `POST /api/cves/distro-feeds/import`). On a
**connected** host the button offers to **download the curated vendor OVAL feeds online**
(RHEL 8/9, Oracle Linux, Ubuntu LTS) into that directory first — and the downloaded files
**persist on disk**, so you can copy `data/cve_feeds/` to an air-gapped host and import
there offline (`?online=true` triggers the fetch):

- **OVAL v2** (XML, `.bz2`/`.gz` ok) — covers **RHEL / CentOS, Oracle Linux (ELSA),
  Rocky / Alma, Ubuntu**. The parser reads the distro + release from each definition,
  so one importer handles them all. (RHEL OVAL also serves CentOS/Rocky/Alma, which track
  RHEL errata; Oracle and Ubuntu publish their own OVAL.)
- **Debian Security Tracker JSON** — a single file covering all Debian releases.

When advisories are loaded for a host's distro, the scan reports a package as vulnerable
**only if its installed version is older than the distro's fixed version** (compared with
the correct **EVR/dpkg** algorithm, honouring epoch and `-release`). The remediation cites
the vendor advisory (RHSA/ELSA/USN). When no feed is loaded for that distro, it falls back
to NVD matching with the backport caveat. *(Windows/MSRC is a planned follow-on and needs
the WinRM scanner.)*

### Matching accuracy & limitations

Correlation is **version-aware**: a service/package is only reported when its detected
version falls inside a CVE's affected version range (parsed from NVD CPE
`versionStart*/versionEnd*`). There is **no** description-keyword guessing. A
service/package with no detectable version produces no findings.

This is a heuristic NVD/CPE matcher, not a distro security feed. Residual false
positives are possible when an OS package shares an exact CPE product name with an
unrelated product (e.g. the Debian `dash` shell vs. the Python "dash" library). For
authoritative, distro-accurate results, pair this with vendor OVAL/security feeds.

---

## Web / URL penetration test checks

All checks are **non-destructive** (no exploitation payloads). For each finding the
platform records a severity, description, evidence, and remediation.

- **Security headers** — flags missing `Strict-Transport-Security` (HSTS),
  `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`.
- **TLS / certificate** — detects cleartext HTTP, deprecated protocols
  (TLS 1.1/1.0/SSLv3), and expired / soon-to-expire certificates.
- **Software fingerprinting** — reads `Server` / `X-Powered-By` banners, reports the
  information disclosure, and **correlates the detected software against the local CVE
  database**.
- **Cookies** — flags session cookies missing `Secure`, `HttpOnly`, or `SameSite`.
- **HTTP methods** — flags dangerous methods (`TRACE`, `TRACK`, `PUT`, `DELETE`,
  `CONNECT`) advertised via `OPTIONS`.
- **Sensitive path exposure** — probes for `/.git/HEAD`, `/.env`, `/.svn/entries`,
  `/server-status`, `/phpinfo.php`, backup archives, `/.DS_Store`, etc.
- **Reflected input** — appends a harmless alphanumeric canary and reports if it is
  reflected unsanitized (a possible XSS sink to test manually). **No script/SQL
  payloads are sent.**

---

## Server vulnerability assessment & CVE correlation

After an nmap scan, every discovered service is matched against the local CVE
database using an **explainable, conservative** strategy. Each finding stores *why*
it matched, so reports are defensible:

1. **CPE product + version match** — the strongest signal. When the service exposes a
   CPE / product+version and a CVE lists an overlapping affected product, it is a
   **high**-confidence match (version-aware). A product match where the version
   differs is recorded as **medium** so it is still surfaced for triage.
2. **Description keyword match** — if the product name appears in the CVE
   description, it is flagged at **low** confidence for analyst review.

Findings are sorted by severity then CVSS so the most serious surface first. CVE
correlation also runs against software identified during web scans.

---

## The local CVE database (offline import)

The platform ships with ~10 well-known sample CVEs (Log4Shell, Heartbleed,
EternalBlue, Ghostcat, Shellshock, Spring4Shell, …) so correlation and reporting work
out of the box. For full coverage, import NVD feeds offline:

1. On an **internet-connected** machine, download NVD JSON feeds, e.g.
   `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz`
   (one file per year; `.json` or `.json.gz`).
2. Transfer the files into `./data/cve_feeds/` on the air-gapped host (mounted into
   both `backend` and `worker` at `/data/cve_feeds`).
3. In the GUI, go to **CVE Database → Import NVD feeds** (admin only), or call
   `POST /api/cves/import`.

**Supported formats:** NVD **1.1** legacy feeds (`CVE_Items`), NVD **2.0** API exports
(`vulnerabilities`), the fkie-cad mirror (`cve_items`), this platform's own
**CVE DB export** (see below), and gzip/xz-compressed variants. Re-importing **updates**
existing records. Imports are batched for bounded memory on large feeds.

### Copying the CVE database to another deployment (export / upload)

A second deployment that can't reach NVD doesn't need to re-download or re-parse the
year feeds — copy the **already-built** database straight across:

1. On a deployment that has the CVEs loaded: **CVE Database → ⬇ Download CVE DB** (or
   `GET /api/cves/export`). This streams the entire CVE table as a single gzipped JSON
   file (`threatprobe-cve-db-YYYYMMDD.json.gz`, ~50 MB for the full NVD set). The export
   streams row-by-row, so it works on the full multi-hundred-thousand-row database
   without spiking memory.
2. Move the file to the target host (USB, internal share, etc.).
3. On the target: **CVE Database → ⬆ Upload CVE DB** (admin) and pick the file (or
   `POST /api/cves/upload`, or just drop it in `data/cve_feeds/` and run Import). The
   upload is streamed to disk and imported with the same batched upsert — new CVEs are
   inserted, existing ones updated.

This is the simplest way to seed an air-gapped install: the heavy NVD parsing was done
once on the source side, so the target just loads finished records.

### Threat-intel enrichment — KEV & EPSS (prioritization)

CVSS tells you how *bad* a vulnerability is, not how *likely* it is to be exploited.
The platform enriches the local CVE database with two industry threat-intel feeds so you
triage on real-world risk:

- **CISA KEV** (Known Exploited Vulnerabilities) — CVEs **actively exploited in the
  wild**. These are flagged with a red **KEV** badge and sorted to the top.
- **FIRST EPSS** (Exploit Prediction Scoring System) — the **probability (0–100%) a CVE
  will be exploited in the next 30 days**, shown as its own column.

Both are small, downloadable files (air-gap friendly). Drop them in `data/cve_feeds/`:

```
known_exploited_vulnerabilities.json   # https://www.cisa.gov/.../known_exploited_vulnerabilities.json
epss_scores-current.csv.gz             # https://epss.cyentia.com/epss_scores-current.csv.gz
```

Then **CVE Database → 🎯 Import KEV / EPSS** (admin), or `POST /api/cves/threat-intel/import`
(add `?online=true` on a connected host to fetch them directly). The online fetch **saves
the downloaded files** into `data/cve_feeds/`, so a connected host produces exactly the
files an air-gapped host needs. Enrichment only updates existing CVEs, so import NVD feeds first.

#### Feed directory — one persistent location for everything

All feed data lives under **`/data/cve_feeds`**, mounted from the host via the `./data:/data`
bind mount in `docker-compose.yml` — it **persists across container rebuilds**. To seed an
air-gapped deployment, copy this one folder across:

```
data/cve_feeds/
├── _auto/CVE-YYYY.json.xz                  NVD CVE feed (online updater keeps it on disk)
├── known_exploited_vulnerabilities.json    CISA KEV
├── epss_scores-current.csv.gz              FIRST EPSS
└── distro_feeds/*.xml.bz2                  vendor OVAL (RHEL / Oracle / Ubuntu …)
```

Findings and the CVE browser are then **risk-ranked**: actively-exploited (KEV) first,
then by EPSS likelihood, then severity/CVSS — so the CVE most likely to be used against
you surfaces at the top instead of being buried among equal-CVSS entries. The CVE browser
also has an **"Exploited (KEV) only"** filter.

For each CVE the importer stores: ID, description, CVSS v3/v2 score and vector,
derived severity, affected product CPEs, **structured affected version ranges**
(`versionStart*/versionEnd*`, used for precise matching), references, CWE, and
heuristic **remediation** guidance.

> **This deployment** currently has NVD years **2016–2026 loaded (~274,800 CVEs)**.
> To add more years, place additional `CVE-YYYY.json.xz` feeds in `data/cve_feeds/`
> and re-import — imports are incremental and idempotent. Supported feed extensions:
> `.json`, `.json.gz`, `.json.xz`.

### Scheduled / automatic CVE updates

On the **CVE Database** page, admins can enable **automatic updates** on an interval
(default every 24 hours). Two sources:

- **Online** — downloads the current-year NVD feed from the fkie-cad mirror and upserts
  it (new CVEs are added, modified ones refreshed). Requires outbound internet.
- **Feed directory (offline)** — re-imports whatever feeds are present in
  `data/cve_feeds/` (the air-gapped path; an operator drops new yearly feeds in).

A background scheduler in the backend runs due updates; **Update now** triggers one
immediately. Endpoints: `GET/PUT /api/cves/update/config`, `POST /api/cves/update/run`.

### Email reports (GUI-configured SMTP)

Configure SMTP under **Settings → Email/SMTP** (host, port, STARTTLS/SSL, credentials,
default recipients) — stored in the database, not in `.env`. From any scan, **Email
report** sends the findings summary (totals + severity breakdown) in the body with the
PDF and/or CSV attached. Endpoints: `GET/PUT /api/settings/smtp`,
`POST /api/settings/smtp/test`, `POST /api/reports/scan/{id}/email`.

---

## Reports (CSV / PDF)

From any scan detail page:

- **CSV** — one row per finding (both CVE and web findings), with columns: type, asset,
  hostname, port/protocol, service/category, product, version, CVE/finding, severity,
  CVSS, confidence, match/evidence, status, description, remediation, references, CWE.
- **PDF** — a styled assessment report containing:
  - a **title page** with scan metadata,
  - an **executive summary** with a severity breakdown,
  - a **host & service inventory**,
  - **detailed CVE findings** (affected asset, status, match rationale, CWE,
    description, remediation, references), and
  - **web/URL findings** (category, severity, evidence, remediation).

Endpoints: `GET /api/reports/scan/{id}/csv` and `GET /api/reports/scan/{id}/pdf`.

### Filtered / consolidated reports

The **Reports** page builds a single report **across scans** (optionally scoped to one
target) with a composable filter set — pick any combination of:

- **Severity** (Critical/High/Medium/Low/Info)
- **Triage status** (open/confirmed/false_positive/fixed/accepted)
- **Finding type** (Server/CVE, Web/URL, Package inventory)
- free-text **host/IP**, **port**, **CVE id**, **package name**
- **match confidence** and **vulnerable-packages-only**

A live **Preview count** shows how many findings match before you export. Download the
filtered result as **PDF** or **CSV**. Backend endpoints:
`GET /api/reports/export.csv`, `GET /api/reports/export.pdf`,
`GET /api/reports/export/preview` (all accept the filter query params
`target_id, severity, status, types, host, port, cve_id, package, confidence,
vulnerable_only`). The PDF caps detailed entries per section (use CSV for the full set).

---

## Offline AI assistant

A built-in chat assistant (floating button, bottom-right) powered by a **small quantized
model running locally** via [llama.cpp](https://github.com/ggml-org/llama.cpp) — it needs
**no internet** and is bundled with the platform, so it works in fully air-gapped sites.

**It is RAG-grounded, not a chatbot that recalls facts.** A small model would hallucinate
CVE IDs, CVSS scores and "fixes", so the backend does the knowing and the model does the
explaining: it detects entities in your question, retrieves authoritative facts from the
**local database**, and instructs the model to answer **using only those facts**. If the
model server is unreachable it falls back to a deterministic summary of the retrieved data,
so the feature still works.

What you can ask:

- **Launch a scan, in chat** — e.g. `run a port scan on 10.0.0.5` or `start a credentialed
  scan on web.lab.local`. A guided wizard collects the **target → scan type → details**
  (SSH username/port and **password or key**, CIS level, or custom nmap flags), **auto-creates
  the target** if it's new, launches via the standard scan API (role + scope-allowlist
  enforced), then **watches the scan and posts a grounded result summary when it completes**.
  Credential steps use a **masked field; the values are held in-memory only and are never
  written to chat history / `localStorage` nor sent to the model** — they go straight to the
  scan request and are dropped immediately. Viewers can't launch.
- **Explain a CVE** — `explain CVE-2023-2975` → severity, CVSS, KEV/EPSS risk, affected
  products and remediation, pulled from your local CVE DB (with the CVE cited).
- **Summarise a scan** — `summarise scan #12` → severity breakdown, top KEV/critical
  findings, web findings, failed CIS controls.
- **Check a package** — backport-aware: which advisories affect it and the distro-fixed version.
- **Explain a vuln class** — XSS, SQLi, SSRF, CSRF, IDOR, path traversal, weak TLS, missing
  CSP/HSTS, CORS, clickjacking — what it is and how to fix it.
- **Prioritised patch plan** — "what should I fix first in scan 94" / "patch plan" → findings
  grouped by package, ordered KEV → severity → CVE count, with the distro-fixed version when
  known (deterministic).
- **Compare scans** — "compare scan 12 and 15" or "what changed since the last scan on
  10.0.0.5" → new vs. resolved vs. unchanged findings (deterministic diff).
- **Take action in chat** — "rescan 94" (re-prompts for credentials on credentialed/CIS),
  "stop scan 95", "schedule a port scan on 10.0.0.5 every 24h" (role-gated; uses the
  standard scan/schedule APIs).

- **Agentic mode (multi-step tool-calling)** — *opt-in* (Settings → AI Assistant). Instead of
  rule-based routing, the model runs a **ReAct loop**: it's given read-only, DB-grounded tools
  (`lookup_cve`, `search_cves`, `package_cves`, `list_scans`, `scan_summary`, `patch_plan`,
  `diff_scans`, `risk_posture`), decides which to call, gets the results, and reasons over
  multiple steps to answer. Facts come from the tools (accurate); the model plans + phrases.
  Needs a **tool-capable model** — load **Qwen2.5-7B-Instruct** via the model manager for
  good results (small models tool-call unreliably). Write-actions stay in the confirmed
  rule-based path; the loop is read-only and falls back to the standard assistant on error.

Architecture: a `llm` service (llama.cpp server, OpenAI-compatible API, started with
`--jinja` for tool templates) serves a GGUF from `./data/models`; `/api/assistant/chat`
builds the grounded prompt and retrieval tools. The scan launcher is a client-side wizard
over the existing `/api/targets` + `/api/scans` endpoints. The model phrases; the DB supplies facts.

**Model & resources.** Default model is **Qwen2.5-1.5B-Instruct (Q4_K_M, ~1 GB)**. Swapping
needs **no code or compose edits** — the `llm` container auto-loads the model named in
`data/models/.active` (else the largest `.gguf` present). Manage models from the GUI under
**Settings → AI Assistant → AI model**: list installed models, **download** from a curated
catalog (Qwen2.5 1.5B/3B/7B, Llama 3.2 3B) or a custom URL into `data/models/`, **select**
the active one, and delete. Selecting a different model takes effect when the engine
restarts (`docker compose up -d llm`). Bump the `llm` `mem_limit` for bigger models
(≈3 GB for 1.5B, ≈5 GB for 3B, ≈8 GB for 7B). On air-gapped hosts, drop the `.gguf` into
`data/models/` manually.

**Local or remote model.** Under **Settings → AI Assistant → AI model source** choose
**local** (the bundled offline model in this deployment) or **remote** — point it at an
**OpenAI-compatible server on another machine** (e.g. a **GPU box** running llama.cpp or
Ollama) by URL, with an optional model name and API key. The assistant/agent call
`<url>/v1/chat/completions` at runtime, so you can keep the lightweight bundled model here
and switch to the GPU box for heavier reasoning whenever it's available — no redeploy. If
the remote is unreachable, answers fall back to the deterministic DB summaries.

**Air-gapped install.** On a connected host the model file downloads into `data/models/`
and the `ghcr.io/ggml-org/llama.cpp:server` image is pulled; copy `data/models/` across and
`docker save`/`load` the image to seed an offline site. (`data/models/` is git-ignored.)

**Enable / disable.** Admins can disable it in one click from the chat header, or toggle it
under **Settings → AI Assistant** (`POST /api/assistant/toggle`). When disabled the widget
is hidden for everyone.

---

## Settings (live, tool-level configuration)

The **Settings** page is tabbed — **General · Email · Scanning · Web/ZAP · Matching & data ·
Security & scope · AI Assistant** — and changes apply at runtime with **no `.env` edit or
rebuild** (stored in the DB, read by the engine via a short-TTL cache). Each section has a
*Reset to defaults*. Highlights:

- **Scanning** — default nmap flags, privileged SYN scan (`-sT`→`-sS`), scan timeout, default scan type.
- **Web/ZAP** — spider & active-scan max minutes, spider depth/children, AJAX minutes/browsers/states.
- **Matching & data** — minimum severity shown (GUI + reports), default CVE sort, **scan
  auto-retention** (a daily cleanup deletes scans older than N days; 0 = keep forever), live-log cap.
- **Security & scope** — session lifetime, password min length, and a **target scope
  allowlist** (CIDR / host globs) enforced at scan creation — a guardrail so scans can only
  hit in-scope assets.

API: `GET/PUT /api/settings/app`, `POST /api/settings/app/reset/{group}`.

---

## Roles & permissions

| Role       | Targets | Scans            | Findings        | CVE import | Users |
|------------|---------|------------------|-----------------|------------|-------|
| `admin`    | ✔       | ✔                | ✔               | ✔          | ✔     |
| `operator` | ✔       | ✔ create/delete  | ✔ triage        | view       | —     |
| `viewer`   | read    | read             | read            | read       | —     |

JWT tokens expire after `ACCESS_TOKEN_EXPIRE_MINUTES` (default 480 = 8 hours).

---

## Data model

```
User(id, username, hashed_password, role, is_active, created_at)
Target(id, name, address, description, tags, created_at)
Scan(id, target_id→Target, scan_type, profile, status, progress, error,
     raw_output, created_by, created_at, started_at, finished_at)
Host(id, scan_id→Scan, address, hostname, state, os_guess)
Service(id, host_id→Host, port, protocol, state, service_name, product,
        version, cpe, banner)
CVE(id, cve_id, description, cvss_v3_score, cvss_v3_vector, cvss_v2_score,
    severity, published, last_modified, cpe_products, references, remediation, cwe)
Finding(id, scan_id→Scan, service_id→Service, cve_id, severity, cvss_score,
        match_confidence, match_reason, status, notes, created_at)   # network/server CVE findings
WebFinding(id, scan_id→Scan, target_url, category, name, severity, cvss_score,
           cve_id, description, evidence, remediation, references, status, created_at)
```

Deleting a target cascades to its scans; deleting a scan cascades to its hosts,
services, and findings. Tables are created automatically on startup.

---

## REST API reference

Base path: `/api` (through the nginx proxy) or directly on the backend at
`http://<backend>:8000`. Interactive Swagger UI: `http://<backend>:8000/docs`.
All endpoints except `POST /api/auth/login` and `GET /api/health` require a
`Authorization: Bearer <token>` header.

**Auth**
- `POST /api/auth/login` — form fields `username`, `password` → `{access_token, role}`
- `GET  /api/auth/me` — current user
- `GET  /api/auth/users` *(admin)* · `POST /api/auth/users` *(admin)* · `DELETE /api/auth/users/{id}` *(admin)*

**Targets**
- `GET /api/targets` · `POST /api/targets` · `GET /api/targets/{id}` · `PUT /api/targets/{id}` · `DELETE /api/targets/{id}`

**Scans**
- `GET  /api/scans` *(optional `?target_id=`)*
- `POST /api/scans` — `{target_id, scan_type, custom_flags?}`
- `GET  /api/scans/{id}` — scan + hosts + services
- `GET  /api/scans/{id}/findings` *(optional `?severity=`)*
- `GET  /api/scans/{id}/web-findings`
- `DELETE /api/scans/{id}`

**Findings (triage)**
- `PATCH /api/findings/{id}` — `{status?, notes?}`
- `PATCH /api/findings/web/{id}` — `{status?}`

**CVEs**
- `GET  /api/cves` *(`?q=&severity=&limit=&offset=`)*
- `GET  /api/cves/count` — totals by severity
- `GET  /api/cves/{cve_id}`
- `POST /api/cves/import` *(admin)* — import feeds from `/data/cve_feeds`

**Reports**
- `GET /api/reports/scan/{id}/csv`
- `GET /api/reports/scan/{id}/pdf`

**Dashboard**
- `GET /api/dashboard/stats`

**Health**
- `GET /api/health`

---

## Configuration (environment variables)

Set in `.env` (consumed by `docker-compose.yml`) or directly in the environment.

| Variable                      | Default                                | Description                              |
|-------------------------------|----------------------------------------|------------------------------------------|
| `POSTGRES_USER`               | `pentest`                              | DB user                                  |
| `POSTGRES_PASSWORD`           | `pentest`                              | DB password                              |
| `POSTGRES_DB`                 | `pentest`                              | DB name                                  |
| `DATABASE_URL`                | derived                                | SQLAlchemy URL (set by compose)          |
| `SECRET_KEY`                  | placeholder                            | JWT signing key — **change this**        |
| `ADMIN_USERNAME`              | `admin`                                | Bootstrap admin username                 |
| `ADMIN_PASSWORD`              | from `.env.example`                    | Bootstrap admin password — **change**    |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480`                                  | JWT lifetime                             |
| `CVE_FEED_DIR`                | `/data/cve_feeds`                      | Where the importer reads NVD feeds       |
| `NMAP_DEFAULT_FLAGS`          | `-sT -sV -T4 --open`                   | Flags for the `full` profile             |
| `SCAN_TIMEOUT_SECONDS`        | `3600`                                 | Hard cap per scan                        |
| `WORKER_POLL_INTERVAL`        | `5`                                    | Worker poll interval (seconds)           |
| `FRONTEND_PORT`               | `8080`                                 | Host HTTP port (redirects to HTTPS)      |
| `FRONTEND_HTTPS_PORT`         | `8443`                                 | Host HTTPS port for the GUI (self-signed)|
| `CORS_ORIGINS`                | `*`                                    | Allowed CORS origins                     |

---

## Air-gapped deployment

Nothing in the platform reaches the internet at runtime, so a fully offline install
is just two transfers: **(1) the container images** and **(2) the CVE data** (either an
exported database or the NVD feeds). Do the internet-dependent steps once on a connected
machine, copy the artifacts across on removable media, and load them on the air-gapped
host.

### 1. Save the container images (on a connected machine)

Build the two app images and pull the two third-party base images, then `docker save`
**all four** into one tarball:

```bash
# In the project directory, with internet access:
docker compose build                       # builds pentest-platform-backend & -frontend
docker compose pull db zap                 # pulls postgres:16-alpine & the ZAP daemon image

docker save \
  pentest-platform-backend \
  pentest-platform-frontend \
  postgres:16-alpine \
  ghcr.io/zaproxy/zaproxy:stable \
  -o pentest-images.tar                     # ~1.5–2 GB (ZAP + browser bundle is the bulk)
```

> `backend` and `worker` share the **same** image, so the three `compose` services
> `backend`/`worker`/`frontend` need only two built images. **Do not omit the ZAP image**
> — it ships the bundled headless Firefox the AJAX spider needs, so authenticated/SPA
> scanning works offline once it's loaded.

### 2. Get the CVE data (on the same connected machine)

You have two options — pick whichever fits:

**(a) Easiest — export an already-loaded database.** If you have another deployment with
CVEs loaded, use **CVE Database → ⬇ Download CVE DB** (or `GET /api/cves/export`) to get a
single `threatprobe-cve-db-*.json.gz` (~50 MB). On the air-gapped host, load it later with
**⬆ Upload CVE DB**. No NVD download or re-parsing needed — see
[Copying the CVE database](#copying-the-cve-database-to-another-deployment-export--upload).

**(b) From NVD directly** — grab the JSON feeds (one `.json.gz` per year, no need to unzip):

```bash
mkdir -p data/cve_feeds
for y in $(seq 2016 2026); do
  curl -L -o data/cve_feeds/nvdcve-1.1-$y.json.gz \
    https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-$y.json.gz
done
```

### 3. Transfer & load (on the air-gapped host)

Copy three things onto the offline host: **`pentest-images.tar`**, the **project
directory** (for `docker-compose.yml` + `.env`), and the **`data/cve_feeds/`** files.

```bash
docker load -i pentest-images.tar      # registers the images locally; no registry pulls
docker compose up -d                   # starts all 5 services from the loaded images
```

Then load the CVEs (one-time, and after each refresh) — matching how you obtained them
in step 2:

- **If you exported a CVE DB (2a):** log in as admin → **CVE Database → ⬆ Upload CVE DB**
  and select the `threatprobe-cve-db-*.json.gz` file (or `POST /api/cves/upload`).
- **If you copied NVD feeds (2b):** **CVE Database → Import NVD feeds**, or
  `POST /api/cves/import` (admin token).

The `./data/cve_feeds` directory is mounted into both `backend` and `worker` at
`/data/cve_feeds`, so the importer reads it directly — see
[The local CVE database](#the-local-cve-database-offline-import) for formats and the
**Scheduled CVE updates** option (point it at `feed_dir` to re-import the offline feeds
on a timer, never the network).

### Keeping an air-gapped install current

Repeat steps 1–3 with newer artifacts: rebuild/save images when the app changes, and
re-download the NVD year files (the current year's file updates daily) to re-import.
Nothing else phones home.

---

## Backup & restore

The database lives in the named volume `pentest-platform_pgdata`.

```bash
# Backup
docker compose exec db pg_dump -U pentest pentest > backup.sql

# Restore (into a fresh stack)
cat backup.sql | docker compose exec -T db psql -U pentest pentest

# Full reset (DESTROYS all data, re-seeds admin + sample CVEs on next start)
docker compose down -v
```

---

## Troubleshooting

- **Backend exits with `password cannot be longer than 72 bytes`** — a known
  `passlib`/`bcrypt` version conflict. `requirements.txt` pins `bcrypt==4.0.1` to
  resolve it; rebuild with `docker compose build backend worker`.
- **Worker logs `nmap=MISSING`** — the worker image didn't install nmap; rebuild the
  worker (`docker compose build worker`).
- **Scans stay `queued`** — the worker isn't running or can't reach the DB. Check
  `docker compose logs worker`.
- **Scan `failed` with "nmap failed" / host down** — the worker container can't reach
  the target. Verify network path and that you used an IP/host the worker can route to.
- **Web scan shows "Target unreachable"** — the URL is wrong or not reachable from the
  worker container; confirm scheme (`http://`/`https://`) and connectivity.
- **`401 Unauthorized` in the GUI** — token expired; log in again.
- **Backend can't connect to DB at startup** — it retries for ~60s waiting for the
  `db` healthcheck; check `docker compose logs db`.

---

## Feature changelog

Major features added over the project's life (newest first). Each is documented in detail
in the section above; commit hashes are on the `main` branch.

| Date | Feature | Commit |
|------|---------|--------|
| 2026-06-25 | **AI: local or remote model source** — point the assistant at an OpenAI-compatible server on a GPU box (URL/model/key) or use the bundled offline model, switchable in Settings. | `(latest)` |
| 2026-06-25 | **AI: agentic mode (ReAct tool-calling)** — opt-in multi-step loop over read-only DB-grounded tools (best on a 7B model); plus a deterministic package-CVE lookup. | `b679e35` |
| 2026-06-25 | **AI: patch plan, scan diff, and chat actions** — "what should I fix first", "what changed since the last scan", and "rescan/stop/schedule" straight from chat. | `69aec2a` |
| 2026-06-24 | **GUI AI-model manager + zero-edit model swap** — list/download/select/delete GGUFs; the engine auto-loads the selected (or largest) model. | `5910a9d` |
| 2026-06-24 | **In-chat scan-launcher wizard** (target → type → credentials → confirm → auto-summary) + per-scan **result counts**. | `816ded9` |
| 2026-06-24 | **Offline RAG-grounded AI assistant** (llama.cpp + bundled GGUF) with enable/disable. | `5dc61b9` |
| 2026-06-24 | **Live tool-level settings** — tabbed, DB-backed, read at runtime (scanning/ZAP/matching/security/AI). | `c288850` |
| 2026-06-24 | **Dashboard graphs** (severity/status/type donuts + 14-day activity), **scan-completion notifications**, global page footer. | `e969dcb` |
| 2026-06-24 | **Vibrant UI refresh** — inline-SVG icon system, KPI cards, brand-matched PDFs, gradient logo/favicon. | `452a85b`, `3286e5c` |
| 2026-06-24 | **Distro feeds online fetch + air-gap persistence**; **Ubuntu OVAL** support. | `8164b81`, `e3b2384` |
| 2026-06-23 | **CIS benchmark scan type** — OpenSCAP L1/L2 Server/Workstation + agentless built-in fallback. | `fd85bfa`, `3fb9f53` |
| 2026-06-23 | **KEV + EPSS** threat-intel enrichment & risk-based prioritization. | `148873c` |
| 2026-06-23 | **Scheduled (recurring) scans**; **stop/cancel**; **rescan**; **white-label branding**. | `c8dcb48`, `d567c15`, `9f400d2` |
| 2026-06-23 | **Per-scan-type PDF/CSV reports** with charts; **distro-accurate (backport-aware)** matching via vendor OVAL. | `91b10a9`, `d527868` |
| 2026-06-23 | **HTTPS GUI** (self-signed); in-app **About** page. | `4955ccc`, `e35da8f` |
| 2026-06-18 | **Authenticated + AJAX/SPA ZAP** scanning; **CVE DB export/upload** for air-gap seeding. | `71e0364`, `bc852e0` |
| 2026-06-11 | **Initial platform** — multi-host targets, GUI SMTP + emailed reports, live scan log, scheduled CVE updates. | `0a9f568`, `0f9a2c6` |

---

## Bug history & fixes

A transparent log of bugs found during development and how they were fixed (newest first).
Commit hashes are on the `main` branch.

| Date | Area | Bug → Fix | Commit |
|------|------|-----------|--------|
| 2026-06-25 | Reports / AI | Report filenames lacked context; AI showed results for still-running scans; AI dumped the whole summary for pointed questions and miscounted ("21" of 484). → Filenames now `target_type_scanID_timestamp_report.*`; running scans return an "in progress" message (wizard waits for completion); pointed questions are answered as focused insights while counts stay deterministic. | `010145c` |
| 2026-06-24 | AI assistant | "scan result of **89**" wasn't recognised (only "scan #N" matched), so the model answered from empty context; intent stems (`summarise`, `vulnerability`) never matched. → Resolve scans by bare number, and fixed stem matching. | `67d7cdf` |
| 2026-06-24 | AI assistant | A scan referenced by **target IP** ("scan on 10.0.10.246") bypassed the deterministic path and the model hallucinated "no findings". → Resolve a target's latest scan from an IP/host. | `e580906` |
| 2026-06-24 | AI assistant | The 1.5B model **inverted CIS counts** — reported a 6-failed scan as "no failures". → Scan summaries are now built deterministically from DB facts (model not used for aggregates). | `e969dcb` |
| 2026-06-24 | Dashboard | "Scans by status" chart looked poor; no scan-completion notification; copyright missing on inner pages. → Status donut + "Scans by type" + 14-day activity chart; global completion toast + browser notification; global page footer. | `e969dcb` |
| 2026-06-24 | Branding / UI | Browser-tab **favicon blank**; default logo showed a white box; AI chat history lost on reload. → Bundled gradient-shield favicon/logo (transparent); chat history persisted with a Clear button. | `3286e5c` |
| 2026-06-24 | Dashboard / Scans | Dashboard finding count ignored **CIS** results; Scans page had no per-scan result count. → Count CVE + web + failed-CIS across all types; added a Results column. | `816ded9` |
| 2026-06-24 | Scan detail | Every scan showed all sections (hosts/ports, web, CVE) regardless of type; wide "CVEs in DB" number overlapped its icon. → Per-scan-type sections; flex KPI layout. | `c964f2b` |
| 2026-06-24 | Feeds / air-gap | Online KEV/EPSS/CVE imports didn't persist the downloaded files, so they couldn't be carried to an air-gapped host; the NVD feed was deleted after import. → Online fetches now save files under `/data/cve_feeds`; the updater keeps the NVD feed. | `8164b81`, `6642166` |
| 2026-06-24 | Distro feeds / CIS | **Ubuntu OVAL imported 0 rows** (its tests live in `extend_definition`s referenced via `var_ref`); CIS output didn't show distro/level. → Transitive `extend_definition` + variable resolution; CIS now shows distro + benchmark level + score. | `e3b2384` |
| 2026-06-23 | Reports | Per-scan-type PDF/CSV reports had **blank columns** (one template for all types). → Dedicated templates per scan type. | `91b10a9` |
| 2026-06-23 | CIS / OpenSCAP | OpenSCAP fell back to built-in checks even when present; rules came back all-`notapplicable` on RHEL clones; remediation was blank; no rule results parsed. → Scored datastream selection preferring clone content, `--results-arf` for remediation, auto-install + stderr surfacing + regex fallback. | `3fb9f53`, `acb3199`, `797cc29`, `79691cd` |
| 2026-06-23 | Navigation | Browser **Back button** from a scan was broken. → Path-based routing with history support; added Rescan. | `9f400d2` |
| 2026-06-23 | Database | `findings.match_reason` overflowed `varchar(255)` (kernel backport caveat). → Widened the column to `TEXT`. | `00b5ce6` |
| 2026-06-23 | CVE matching | Kernel packages weren't correlated to CVEs (product-name mismatch). → `linux_kernel` product alias (refined to avoid false positives). | `ef38fe8` |
| 2026-06-19 | Web / ZAP | Authenticated ZAP scans on **SPAs** returned empty results. → Bearer/token session handling + AJAX spider fixes. | `20d037b` |
| 2026-06-11 | Web / ZAP | ZAP **OOM-restarted** on real/large targets during active scans. → Bounded crawl/scan scope + JVM memory caps + `shm_size`. | `cecdaa4`, `c306692` |
| 2026-06-11 | UI | Stale cached CSS/JS served after updates; severity/CVE labels wrapped onto multiple lines. → Asset cache-busting (`?v=N`); nowrap badge/label styling. | `23ea908`, `c77cacd` |

---

## Authorization & scope

This tool is for **authorized** security testing only. Scan and test **only** systems
you own or have **explicit written permission** to assess. The web checks are
non-destructive (no exploitation or injection payloads are sent), but you remain fully
responsible for operating within your rules of engagement and applicable law.

---

© 2026 ThreatProbe Scanner. All rights reserved.
