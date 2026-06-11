"""nmap wrapper: runs a scan and parses the XML output into structured results.

Designed to fail gracefully: if nmap is missing or the target is unreachable,
the scan is marked failed with a clear error instead of crashing the worker.
"""
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional

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


def run_scan(target_address: str, scan_type: str = "full",
             custom_flags: Optional[str] = None) -> ScanResult:
    """Run nmap against target_address and return parsed results.

    Raises RuntimeError on environment/execution problems with a readable message.
    """
    if not nmap_available():
        raise RuntimeError(
            "nmap is not installed in this container. Rebuild the worker image."
        )

    flags = build_flags(scan_type, custom_flags)
    # Always request XML on stdout for reliable parsing.
    cmd = ["nmap", *flags.split(), "-oX", "-", target_address]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=settings.scan_timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Scan timed out after {settings.scan_timeout_seconds}s")
    except FileNotFoundError:
        raise RuntimeError("nmap binary not found")

    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"nmap failed: {proc.stderr.strip() or 'unknown error'}")

    hosts = parse_nmap_xml(proc.stdout)
    return ScanResult(hosts=hosts, raw_xml=proc.stdout, flags=flags)


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
