"""CIS-style host-hardening checks for credentialed (SSH) Linux assessments.

Each check runs a single READ-ONLY command over the already-open SSH session and an
evaluator turns the output into a result. Nothing is modified on the target. Checks are
best-effort and distro-agnostic where possible; a check that can't run (e.g. needs root
and the scan account lacks it) is reported as `error` rather than a false pass/fail.

This complements the package/CVE audit: it surfaces configuration weaknesses (weak SSH
config, password policy, missing ASLR/firewall/audit, world-writable dirs, legacy
services) that no CVE feed will ever tell you about.
"""
from dataclasses import dataclass
from typing import Callable, List


@dataclass
class HardeningResult:
    check_id: str
    title: str
    severity: str          # CRITICAL/HIGH/MEDIUM/LOW/INFO
    status: str            # fail | pass | error
    detail: str = ""
    remediation: str = ""
    evidence: str = ""


def _first_line(text: str) -> str:
    for ln in (text or "").splitlines():
        if ln.strip():
            return ln.strip()
    return ""


def _check_permit_root_login(ex) -> HardeningResult:
    out = ex("grep -RhiE '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config "
             "/etc/ssh/sshd_config.d/ 2>/dev/null | tail -1")
    val = ""
    parts = _first_line(out).split()
    if len(parts) >= 2:
        val = parts[1].lower()
    base = dict(check_id="ssh-permit-root-login", title="SSH root login permitted",
                severity="HIGH",
                remediation="Set 'PermitRootLogin no' (or 'prohibit-password') in "
                            "/etc/ssh/sshd_config and restart sshd.")
    if not val:
        return HardeningResult(**base, status="error",
                               detail="PermitRootLogin not set explicitly (relying on the "
                                      "sshd default — verify it is hardened).",
                               evidence="no explicit PermitRootLogin directive")
    if val in ("no", "prohibit-password", "without-password"):
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail=f"PermitRootLogin {val}.", evidence=f"PermitRootLogin {val}")
    return HardeningResult(**base, status="fail",
                           detail=f"Direct root SSH login is allowed (PermitRootLogin {val}).",
                           evidence=f"PermitRootLogin {val}")


def _check_password_auth(ex) -> HardeningResult:
    out = ex("grep -RhiE '^[[:space:]]*PasswordAuthentication' /etc/ssh/sshd_config "
             "/etc/ssh/sshd_config.d/ 2>/dev/null | tail -1")
    parts = _first_line(out).split()
    val = parts[1].lower() if len(parts) >= 2 else ""
    base = dict(check_id="ssh-password-auth", title="SSH password authentication enabled",
                severity="LOW",
                remediation="Prefer key-based auth: set 'PasswordAuthentication no' once "
                            "keys are deployed, to remove password brute-force exposure.")
    if val == "no":
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="Password authentication disabled (key-based).",
                               evidence="PasswordAuthentication no")
    return HardeningResult(**base, status="fail",
                           detail="SSH accepts password authentication (brute-force exposure).",
                           evidence=f"PasswordAuthentication {val or 'default(yes)'}")


def _check_uid0_accounts(ex) -> HardeningResult:
    out = ex("awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null")
    users = [u.strip() for u in out.splitlines() if u.strip()]
    extra = [u for u in users if u != "root"]
    base = dict(check_id="uid0-accounts", title="Non-root account with UID 0", severity="HIGH",
                remediation="Only 'root' should have UID 0. Investigate and remove/relabel "
                            "any other UID-0 account.")
    if not users:
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="Could not read /etc/passwd.", evidence="")
    if extra:
        return HardeningResult(**base, status="fail",
                               detail=f"Accounts other than root have UID 0: {', '.join(extra)}.",
                               evidence=", ".join(extra))
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="Only root has UID 0.", evidence="root")


def _check_empty_passwords(ex) -> HardeningResult:
    out = ex("awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null")
    base = dict(check_id="empty-passwords", title="Account with empty password",
                severity="CRITICAL",
                remediation="Lock or set a password for any account with an empty password "
                            "field (passwd -l <user>).")
    # Distinguish "no rows" from "permission denied" — _exec drops stderr, so an empty
    # result on /etc/shadow usually means either none (good) or no read access.
    probe = ex("test -r /etc/shadow && echo READABLE || echo NOACCESS").strip()
    users = [u.strip() for u in out.splitlines() if u.strip()]
    if "READABLE" not in probe:
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="/etc/shadow not readable by the scan account "
                                      "(run the credentialed scan with sufficient privilege).",
                               evidence="no read access to /etc/shadow")
    if users:
        return HardeningResult(**base, status="fail",
                               detail=f"Accounts have an empty password: {', '.join(users)}.",
                               evidence=", ".join(users))
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="No accounts with empty passwords.", evidence="")


def _check_password_max_age(ex) -> HardeningResult:
    out = ex("grep -E '^[[:space:]]*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | tail -1")
    parts = _first_line(out).split()
    base = dict(check_id="pass-max-days", title="Weak password expiry policy", severity="LOW",
                remediation="Set PASS_MAX_DAYS to 365 or less in /etc/login.defs.")
    try:
        days = int(parts[1])
    except (IndexError, ValueError):
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="PASS_MAX_DAYS not found in /etc/login.defs.", evidence="")
    if days <= 365:
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail=f"PASS_MAX_DAYS={days}.", evidence=f"PASS_MAX_DAYS {days}")
    return HardeningResult(**base, status="fail",
                           detail=f"Passwords never effectively expire (PASS_MAX_DAYS={days}).",
                           evidence=f"PASS_MAX_DAYS {days}")


def _check_aslr(ex) -> HardeningResult:
    out = ex("sysctl -n kernel.randomize_va_space 2>/dev/null || "
             "cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
    val = _first_line(out)
    base = dict(check_id="aslr", title="ASLR not fully enabled", severity="MEDIUM",
                remediation="Set kernel.randomize_va_space=2 (sysctl) for full address-space "
                            "layout randomization.")
    if val == "2":
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="ASLR fully enabled (randomize_va_space=2).",
                               evidence="randomize_va_space 2")
    if not val:
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="Could not read kernel.randomize_va_space.", evidence="")
    return HardeningResult(**base, status="fail",
                           detail=f"ASLR not fully enabled (randomize_va_space={val}).",
                           evidence=f"randomize_va_space {val}")


def _check_ip_forward(ex) -> HardeningResult:
    out = ex("sysctl -n net.ipv4.ip_forward 2>/dev/null || "
             "cat /proc/sys/net/ipv4/ip_forward 2>/dev/null")
    val = _first_line(out)
    base = dict(check_id="ip-forward", title="IP forwarding enabled", severity="LOW",
                remediation="If this host is not a router/gateway, set net.ipv4.ip_forward=0.")
    if val == "0":
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="IP forwarding disabled.", evidence="ip_forward 0")
    if not val:
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="Could not read net.ipv4.ip_forward.", evidence="")
    return HardeningResult(**base, status="fail",
                           detail="IP forwarding is enabled (expected only on routers).",
                           evidence=f"ip_forward {val}")


def _check_firewall(ex) -> HardeningResult:
    out = ex("(systemctl is-active firewalld ufw nftables iptables 2>/dev/null; "
             "ufw status 2>/dev/null | head -1; "
             "iptables -S 2>/dev/null | grep -vE '^-P (INPUT|FORWARD|OUTPUT) ACCEPT' | head -1) "
             "2>/dev/null")
    text = (out or "").lower()
    base = dict(check_id="firewall", title="No active host firewall detected", severity="MEDIUM",
                remediation="Enable a host firewall (firewalld/ufw/nftables) with a default-deny "
                            "inbound policy.")
    active = ("active" in text or "status: active" in text
              or any(ln.startswith("-a") for ln in text.splitlines()))
    if active:
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="A host firewall appears active.",
                               evidence=_first_line(out)[:120])
    return HardeningResult(**base, status="fail",
                           detail="No active host firewall detected (firewalld/ufw/nftables/iptables).",
                           evidence=_first_line(out)[:120] or "no firewall active")


def _check_auditd(ex) -> HardeningResult:
    out = ex("systemctl is-active auditd 2>/dev/null; pgrep -x auditd >/dev/null 2>&1 "
             "&& echo running")
    text = (out or "").lower()
    base = dict(check_id="auditd", title="Audit daemon (auditd) not running", severity="LOW",
                remediation="Install and enable auditd for security-relevant event logging.")
    if "active" in text or "running" in text:
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="auditd is running.", evidence="auditd active")
    return HardeningResult(**base, status="fail",
                           detail="auditd is not running — no kernel audit trail.",
                           evidence="auditd inactive")


def _check_legacy_services(ex) -> HardeningResult:
    out = ex("for b in telnetd in.telnetd rshd rlogind vsftpd tftpd; do "
             "command -v $b >/dev/null 2>&1 && echo $b; done 2>/dev/null")
    found = [b.strip() for b in out.splitlines() if b.strip()]
    base = dict(check_id="legacy-services", title="Legacy insecure service installed",
                severity="HIGH",
                remediation="Remove cleartext/legacy services (telnet/rsh/rlogin/tftp) and use "
                            "SSH/SFTP instead.")
    if found:
        return HardeningResult(**base, status="fail",
                               detail=f"Legacy/insecure service binaries present: {', '.join(found)}.",
                               evidence=", ".join(found))
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="No legacy telnet/rsh/tftp service binaries found.", evidence="")


def _check_world_writable_dirs(ex) -> HardeningResult:
    # Bounded so it never hangs a scan on a huge filesystem.
    out = ex("timeout 25 find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) "
             "-print 2>/dev/null | head -10")
    dirs = [d.strip() for d in out.splitlines() if d.strip()]
    base = dict(check_id="world-writable-dirs",
                title="World-writable directory without sticky bit", severity="MEDIUM",
                remediation="Add the sticky bit (chmod +t) or remove world-write on these "
                            "directories to prevent file-tampering by any user.")
    if dirs:
        return HardeningResult(**base, status="fail",
                               detail=f"{len(dirs)} world-writable dir(s) without the sticky bit "
                                      "(showing up to 10).",
                               evidence="; ".join(dirs))
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="No world-writable directories without sticky bit found.",
                           evidence="")


def _grep_check(check_id, title, severity, cmd, bad_when_found, remediation,
                pass_detail, fail_detail):
    """Helper for simple 'run a command; if it produces output it's a finding' checks."""
    def _fn(ex):
        out = _first_line(ex(cmd))
        base = dict(check_id=check_id, title=title, remediation=remediation)
        hit = bool(out)
        is_fail = hit if bad_when_found else not hit
        if is_fail:
            return HardeningResult(**base, severity=severity, status="fail",
                                   detail=fail_detail, evidence=out[:160])
        return HardeningResult(**base, severity="INFO", status="pass",
                               detail=pass_detail, evidence=out[:160])
    return _fn


def _check_ssh_x11(ex) -> HardeningResult:
    out = ex("grep -RhiE '^[[:space:]]*X11Forwarding' /etc/ssh/sshd_config "
             "/etc/ssh/sshd_config.d/ 2>/dev/null | tail -1")
    val = (_first_line(out).split() or ["", ""])[1].lower() if _first_line(out) else ""
    base = dict(check_id="ssh-x11-forwarding", title="SSH X11 forwarding enabled",
                severity="LOW", remediation="Set 'X11Forwarding no' in sshd_config.")
    if val == "yes":
        return HardeningResult(**base, status="fail", detail="X11Forwarding is enabled.",
                               evidence="X11Forwarding yes")
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="X11 forwarding not enabled.", evidence=val or "default")


def _check_umask(ex) -> HardeningResult:
    out = ex("grep -RhiE '^[[:space:]]*UMASK' /etc/login.defs 2>/dev/null | tail -1")
    parts = _first_line(out).split()
    base = dict(check_id="umask", title="Weak default UMASK", severity="LOW",
                remediation="Set UMASK to 027 (or 077) in /etc/login.defs.")
    val = parts[1] if len(parts) >= 2 else ""
    if val and val.lstrip("0") in ("27", "77", "37"):  # 027/077/037
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail=f"UMASK {val}.", evidence=f"UMASK {val}")
    if not val:
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="UMASK not found in /etc/login.defs.", evidence="")
    return HardeningResult(**base, status="fail",
                           detail=f"Default UMASK is permissive (UMASK {val}).",
                           evidence=f"UMASK {val}")


def _check_password_min_len(ex) -> HardeningResult:
    out = ex("grep -RhiE '^[^#]*minlen' /etc/security/pwquality.conf "
             "/etc/security/pwquality.conf.d/ /etc/pam.d/ 2>/dev/null | tail -1")
    base = dict(check_id="password-min-len", title="No minimum password length policy",
                severity="LOW",
                remediation="Set minlen >= 14 in /etc/security/pwquality.conf (or pam_pwquality).")
    if "minlen" in out.lower():
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="A minimum password length is configured.",
                               evidence=_first_line(out)[:120])
    return HardeningResult(**base, status="fail",
                           detail="No minimum password-length (pwquality/pam) policy found.",
                           evidence="no minlen directive")


def _check_cramfs_modules(ex) -> HardeningResult:
    # Unneeded filesystem kernel modules that should be disabled (CIS 1.1.1.x).
    out = ex("for m in cramfs freevxfs jffs2 hfs hfsplus udf; do "
             "lsmod 2>/dev/null | grep -qw $m && echo $m; done")
    loaded = [m.strip() for m in out.splitlines() if m.strip()]
    base = dict(check_id="unused-filesystems", title="Unneeded filesystem module loaded",
                severity="LOW",
                remediation="Disable unused filesystem modules (cramfs/freevxfs/jffs2/hfs/"
                            "hfsplus/udf) via modprobe blacklist.")
    if loaded:
        return HardeningResult(**base, status="fail",
                               detail=f"Unneeded filesystem modules loaded: {', '.join(loaded)}.",
                               evidence=", ".join(loaded))
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="No unneeded filesystem modules loaded.", evidence="")


def _check_core_dumps(ex) -> HardeningResult:
    out = ex("sysctl -n fs.suid_dumpable 2>/dev/null || cat /proc/sys/fs/suid_dumpable 2>/dev/null")
    val = _first_line(out)
    base = dict(check_id="suid-dumpable", title="SUID core dumps allowed", severity="LOW",
                remediation="Set fs.suid_dumpable=0 to prevent SUID programs dumping core.")
    if val == "0":
        return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                               detail="SUID core dumps disabled.", evidence="suid_dumpable 0")
    if not val:
        return HardeningResult(**{**base, "severity": "INFO"}, status="error",
                               detail="Could not read fs.suid_dumpable.", evidence="")
    return HardeningResult(**base, status="fail",
                           detail=f"SUID programs may dump core (suid_dumpable={val}).",
                           evidence=f"suid_dumpable {val}")


def _check_unconfined_perms(ex) -> HardeningResult:
    # SUID/SGID files are expected, but a quick world-writable *file* scan is high value.
    out = ex("timeout 25 find / -xdev -type f -perm -0002 2>/dev/null | head -10")
    files = [f.strip() for f in out.splitlines() if f.strip()]
    base = dict(check_id="world-writable-files", title="World-writable file present",
                severity="MEDIUM",
                remediation="Remove world-write (chmod o-w) from these files.")
    if files:
        return HardeningResult(**base, status="fail",
                               detail=f"{len(files)} world-writable file(s) (showing up to 10).",
                               evidence="; ".join(files))
    return HardeningResult(**{**base, "severity": "INFO"}, status="pass",
                           detail="No world-writable files found.", evidence="")


_CHECKS = [
    _check_permit_root_login,
    _check_password_auth,
    _check_ssh_x11,
    _check_uid0_accounts,
    _check_empty_passwords,
    _check_password_max_age,
    _check_password_min_len,
    _check_umask,
    _check_aslr,
    _check_ip_forward,
    _check_core_dumps,
    _check_firewall,
    _check_auditd,
    _check_legacy_services,
    _check_cramfs_modules,
    _check_world_writable_dirs,
    _check_unconfined_perms,
    # Simple presence/sysctl checks via the _grep_check helper:
    _grep_check("rsyslog", "System logging (rsyslog/syslog) not running", "LOW",
                "(systemctl is-active rsyslog syslog-ng 2>/dev/null; pgrep -x rsyslogd "
                ">/dev/null 2>&1 && echo running) | grep -E 'active|running' | head -1",
                bad_when_found=False,
                remediation="Enable rsyslog (or syslog-ng) so security events are recorded.",
                pass_detail="A system logger is running.",
                fail_detail="No system logging daemon (rsyslog/syslog-ng) active."),
    _grep_check("ssh-root-empty-pw", "SSH permits empty passwords", "HIGH",
                "grep -RhiE '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' "
                "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null | head -1",
                bad_when_found=True,
                remediation="Set 'PermitEmptyPasswords no' in sshd_config.",
                pass_detail="SSH does not permit empty passwords.",
                fail_detail="SSH is configured to permit empty passwords."),
    _grep_check("cron-perms", "World-accessible cron configuration", "LOW",
                "find /etc/cron* -maxdepth 1 -perm -0002 2>/dev/null | head -3",
                bad_when_found=True,
                remediation="Remove world-write from /etc/cron* (chmod o-w; root-owned 0600/0700).",
                pass_detail="Cron configuration is not world-writable.",
                fail_detail="World-writable cron configuration found."),
]


def run_hardening_checks(exec_fn: Callable[[str], str]) -> List[HardeningResult]:
    """Run all hardening checks using exec_fn(cmd)->stdout. Never raises."""
    results = []
    for check in _CHECKS:
        try:
            results.append(check(exec_fn))
        except Exception as exc:  # noqa: BLE001 - one bad check must not abort the rest
            results.append(HardeningResult(
                check_id=getattr(check, "__name__", "unknown"),
                title="Hardening check error", severity="INFO", status="error",
                detail=str(exc)[:200]))
    return results
