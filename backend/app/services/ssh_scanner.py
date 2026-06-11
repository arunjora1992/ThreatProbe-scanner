"""Credentialed (authenticated) Linux assessment over SSH.

Logs into a target host with operator-supplied credentials, enumerates the OS and
the full installed-package inventory (dpkg or rpm), and returns it for CVE
correlation. This finds vulnerable packages that are NOT exposed on any network
port (e.g. bash/Shellshock, glibc, a log4j jar) — the main blind spot of remote
banner-based scanning.

Credentials are passed in as arguments and used only for the lifetime of the
collection. They are NEVER persisted or logged by this module.
"""
import io
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import paramiko

CONNECT_TIMEOUT = 20
EXEC_TIMEOUT = 60


@dataclass
class HostFacts:
    os_name: str = ""
    os_version: str = ""
    kernel: str = ""
    packages: List[Tuple[str, str, str]] = field(default_factory=list)  # (name, clean_version, full_version)


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


def _exec(client: paramiko.SSHClient, cmd: str) -> str:
    stdin, stdout, stderr = client.exec_command(cmd, timeout=EXEC_TIMEOUT)
    return stdout.read().decode("utf-8", errors="replace")


def _parse_os_release(text: str) -> Tuple[str, str]:
    name = version = ""
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            name = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("VERSION_ID=") and not version:
            version = line.split("=", 1)[1].strip().strip('"')
    return name, version


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


def collect_host_facts(
    host: str,
    port: int = 22,
    username: str = "",
    password: Optional[str] = None,
    key_text: Optional[str] = None,
    key_passphrase: Optional[str] = None,
) -> HostFacts:
    """Connect over SSH and gather OS + installed-package facts.

    Raises RuntimeError with a readable message on connection/auth failure.
    """
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

    try:
        facts = HostFacts()
        os_rel = _exec(client, "cat /etc/os-release 2>/dev/null")
        facts.os_name, facts.os_version = _parse_os_release(os_rel)
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
