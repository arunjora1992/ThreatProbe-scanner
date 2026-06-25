"""Credentialed (authenticated) Linux assessment over SSH.

Two independent collections, exposed as two scan types:

  * collect_host_facts()  — package/CVE audit: OS + full installed-package inventory
    (dpkg or rpm) for CVE correlation. Finds vulnerable packages not exposed on any
    network port (bash/Shellshock, glibc, a log4j jar) — the blind spot of remote scans.

  * collect_compliance()  — CIS-benchmark / hardening audit: runs the official CIS
    profile via OpenSCAP when available, else a built-in set of read-only hardening
    checks.

Credentials are passed in as arguments and used only for the lifetime of the
collection. They are NEVER persisted or logged by this module.
"""
import io
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import paramiko

from . import app_settings, hardening, openscap

CONNECT_TIMEOUT = 20
EXEC_TIMEOUT = 60


@dataclass
class HostFacts:
    os_name: str = ""
    os_version: str = ""       # VERSION_ID
    os_id: str = ""            # ID (debian/ubuntu/rhel/centos/…)
    kernel: str = ""
    packages: List[Tuple[str, str, str]] = field(default_factory=list)  # (name, clean_version, full_version)


@dataclass
class ComplianceResult:
    os_name: str = ""
    os_version: str = ""
    mode: str = ""             # "openscap" | "builtin"
    profile: str = ""          # CIS profile id (openscap)
    datastream: str = ""
    score: Optional[float] = None
    reason: str = ""           # why the built-in fallback was used (if it was)
    results: List["hardening.HardeningResult"] = field(default_factory=list)


def _clean_version(full: str) -> str:
    """Reduce a distro package version to the upstream version for CVE matching.

    '1:2.4.49-1ubuntu1.2' -> '2.4.49' ; '2.4.49-1.el8' -> '2.4.49'
    """
    v = full
    if ":" in v:  # strip epoch
        v = v.split(":", 1)[1]
    v = v.split("-", 1)[0]  # strip distro release
    v = v.split("+", 1)[0]
    return v.strip()


def _load_pkey(key_text: str, passphrase: Optional[str]):
    """Try to load a private key string as any supported key type."""
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(key_text), password=passphrase or None)
        except (paramiko.SSHException, ValueError):
            continue
    raise RuntimeError("Could not parse the provided private key (unsupported format or wrong passphrase).")


def _exec(client: paramiko.SSHClient, cmd: str, timeout: int = EXEC_TIMEOUT) -> str:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    return stdout.read().decode("utf-8", errors="replace")


def _parse_os_release(text: str) -> Tuple[str, str, str]:
    name = version = os_id = ""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID=") and not version:
            version = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("ID=") and not os_id:
            os_id = line.split("=", 1)[1].strip().strip('"').lower()
    return name, version, os_id


def _parse_packages(dpkg_out: str, rpm_out: str) -> List[Tuple[str, str, str]]:
    pkgs = []
    for line in dpkg_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0]:
            pkgs.append((parts[0].split(":")[0].lower(), _clean_version(parts[1]), parts[1]))
    for line in rpm_out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0]:
            pkgs.append((parts[0].lower(), _clean_version(parts[1]), parts[1]))
    return pkgs


def _connect(host, port, username, password, key_text, key_passphrase) -> paramiko.SSHClient:
    """Open an SSH client. Raises RuntimeError with a readable message on failure."""
    client = paramiko.SSHClient()
    # In an air-gapped lab the operator scans hosts whose keys aren't pre-trusted.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = dict(
        hostname=host, port=port, username=username,
        timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT,
        allow_agent=False, look_for_keys=False,
    )
    try:
        if key_text:
            connect_kwargs["pkey"] = _load_pkey(key_text, key_passphrase)
        else:
            connect_kwargs["password"] = password
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        raise RuntimeError("SSH authentication failed (check username/password/key).")
    except (paramiko.SSHException, OSError) as exc:
        raise RuntimeError(f"SSH connection failed: {exc}")
    return client


def collect_host_facts(
    host: str,
    port: int = 22,
    username: str = "",
    password: Optional[str] = None,
    key_text: Optional[str] = None,
    key_passphrase: Optional[str] = None,
) -> HostFacts:
    """Connect over SSH and gather OS + installed-package facts (package/CVE audit)."""
    client = _connect(host, port, username, password, key_text, key_passphrase)
    try:
        facts = HostFacts()
        os_rel = _exec(client, "cat /etc/os-release 2>/dev/null")
        facts.os_name, facts.os_version, facts.os_id = _parse_os_release(os_rel)
        facts.kernel = _exec(client, "uname -r 2>/dev/null").strip()
        dpkg_out = _exec(client, "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null")
        rpm_out = ""
        if not dpkg_out.strip():
            rpm_out = _exec(client, "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null")
        facts.packages = _parse_packages(dpkg_out, rpm_out)
        if not facts.packages:
            raise RuntimeError(
                "Connected, but could not enumerate packages (no dpkg/rpm output). "
                "Is this a Linux host with dpkg or rpm?"
            )
        return facts
    finally:
        client.close()


def collect_compliance(
    host: str,
    port: int = 22,
    username: str = "",
    password: Optional[str] = None,
    key_text: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    prefer_profile: str = "",
    log=None,
) -> ComplianceResult:
    """Run a CIS-benchmark audit over SSH: OpenSCAP if present, else built-in checks."""
    client = _connect(host, port, username, password, key_text, key_passphrase)
    try:
        cr = ComplianceResult()
        os_rel = _exec(client, "cat /etc/os-release 2>/dev/null")
        cr.os_name, cr.os_version, os_id = _parse_os_release(os_rel)

        def ex(cmd, timeout=EXEC_TIMEOUT):
            return _exec(client, cmd, timeout=timeout)

        # oscap eval over a full benchmark can take many minutes on a slow host — give it
        # a generous, GUI-configurable cap. On timeout/error, fall back to built-in checks
        # instead of failing the whole scan.
        oscap_to = app_settings.get_int("cis_oscap_timeout_seconds")
        scap = None
        try:
            scap = openscap.run(lambda c: ex(c, timeout=oscap_to), os_id, cr.os_version,
                                prefer_profile, log=log)
        except Exception as exc:  # noqa: BLE001 - timeout/transport → graceful fallback
            log(f"OpenSCAP evaluation did not finish ({exc}); falling back to built-in checks.")
        if scap and scap.available:
            cr.mode = "openscap"
            cr.profile, cr.datastream, cr.score = scap.profile, scap.datastream, scap.score
            cr.results = scap.results
        else:
            cr.mode = "builtin"
            cr.reason = scap.reason if scap else (
                f"OpenSCAP eval exceeded {oscap_to}s (slow host) or errored")
            cr.results = hardening.run_hardening_checks(lambda c: ex(c, timeout=40))
        return cr
    finally:
        client.close()
