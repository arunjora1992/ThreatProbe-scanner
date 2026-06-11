"""nmap wrapper: runs a scan and parses the XML output into structured results.

Designed to fail gracefully: if nmap is missing or the target is unreachable,
the scan is marked failed with a clear error instead of crashing the worker.
"""
import shutil
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..config import settings

# Built-in scan profiles -> nmap flags. "custom" is supplied by the user.
SCAN_PROFILES = {
    "discovery": "-sn",  # host discovery / ping sweep only
    "port": "-sT -T4 --open",  # open ports, no version detection
    "full": settings.nmap_default_flags,  # connect scan + service/version detection
}


@dataclass
class ParsedService:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""
    banner: str = ""


@dataclass
class ParsedHost:
    address: str
    hostname: str = ""
    state: str = "up"
    os_guess: str = ""
    services: List[ParsedService] = field(default_factory=list)


@dataclass
class ScanResult:
    hosts: List[ParsedHost]
    raw_xml: str
    flags: str


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def build_flags(scan_type: str, custom_flags: Optional[str]) -> str:
    if scan_type == "custom" and custom_flags:
        return custom_flags.strip()
    return SCAN_PROFILES.get(scan_type, SCAN_PROFILES["full"])


def expand_targets(address: str) -> List[str]:
    """Split a target's address field into individual nmap targets.

    Supports multiple IPs/hostnames/CIDRs separated by commas, whitespace, or newlines,
    e.g. "10.0.0.1, 10.0.0.2  10.0.0.0/24".
    """
    parts = address.replace(",", " ").replace("\n", " ").split()
    return [p.strip() for p in parts if p.strip()]


def run_scan(target_address: str, scan_type: str = "full",
             custom_flags: Optional[str] = None,
             log_cb: Optional[Callable[[str], None]] = None) -> ScanResult:
    """Run nmap against one or more targets and return parsed results.

    If log_cb is given, nmap's live progress (stderr, via --stats-every) is streamed
    to it for the GUI terminal view. Raises RuntimeError on failure.
    """
    if not nmap_available():
        raise RuntimeError(
            "nmap is not installed in this container. Rebuild the worker image."
        )

    flags = build_flags(scan_type, custom_flags)
    targets = expand_targets(target_address) or [target_address]
    # Always request XML on stdout for reliable parsing; --stats-every gives live progress.
    cmd = ["nmap", *flags.split(), "--stats-every", "3s", "-oX", "-", *targets]
    if log_cb:
        log_cb(f"$ {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        raise RuntimeError("nmap binary not found")

    # Stream stderr (progress) live to the callback while stdout (XML) is collected.
    def _pump_stderr():
        try:
            for line in proc.stderr:
                line = line.rstrip()
                if line and log_cb:
                    log_cb(line)
        except Exception:
            pass

    t = threading.Thread(target=_pump_stderr, daemon=True)
    t.start()
    try:
        stdout, _ = proc.communicate(timeout=settings.scan_timeout_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError(f"Scan timed out after {settings.scan_timeout_seconds}s")
    t.join(timeout=2)

    if proc.returncode != 0 and not (stdout or "").strip():
        raise RuntimeError("nmap failed (no output)")

    hosts = parse_nmap_xml(stdout or "")
    if log_cb:
        log_cb(f"nmap finished: {len(hosts)} host(s) up")
    return ScanResult(hosts=hosts, raw_xml=stdout or "", flags=flags)


def parse_nmap_xml(xml_text: str) -> List[ParsedHost]:
    """Parse nmap -oX output into ParsedHost objects."""
    hosts: List[ParsedHost] = []
    if not xml_text.strip():
        return hosts
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") == "down":
            continue

        address = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                address = addr_el.get("addr", "")
                break
        if not address:
            continue

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        os_guess = ""
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.get("name", "")

        phost = ParsedHost(
            address=address,
            hostname=hostname,
            state="up",
            os_guess=os_guess,
        )

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                pstate_el = port_el.find("state")
                pstate = pstate_el.get("state", "") if pstate_el is not None else ""
                if pstate != "open":
                    continue
                svc_el = port_el.find("service")
                product = name = version = cpe = ""
                if svc_el is not None:
                    name = svc_el.get("name", "")
                    product = svc_el.get("product", "")
                    version = svc_el.get("version", "")
                    cpe_el = svc_el.find("cpe")
                    if cpe_el is not None and cpe_el.text:
                        cpe = cpe_el.text
                banner = " ".join(p for p in [product, version] if p)
                phost.services.append(
                    ParsedService(
                        port=int(port_el.get("portid", "0")),
                        protocol=port_el.get("protocol", "tcp"),
                        state=pstate,
                        service_name=name,
                        product=product,
                        version=version,
                        cpe=cpe,
                        banner=banner,
                    )
                )
        hosts.append(phost)
    return hosts
