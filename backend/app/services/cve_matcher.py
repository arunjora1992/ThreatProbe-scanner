"""Correlate discovered services / installed packages against the local CVE DB.

Precise, version-aware matching (low false-positive):
  1. Find candidate CVEs whose affected-product index mentions the product.
  2. For each candidate, parse the structured `affected` ranges and confirm the
     installed version falls inside an affected range (exact, or bounded by
     versionStart*/versionEnd*). Only then is it a finding.
  3. No description-keyword fallback (that produced large amounts of noise at
     full-NVD scale). A service/package with no detectable version yields no
     findings rather than guesses.

Each finding records the matched range and the version to upgrade to, so the
remediation states exactly which version fixes it.
"""
import json
import re
from typing import List, Optional, Tuple

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..models import CVE, Service

_SEV_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0, "UNKNOWN": 0}


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9.]+", " ", (text or "").lower()).strip()


def _parse_version(v: str) -> Optional[tuple]:
    """Parse a version string into a comparable tuple of (int, suffix) components.

    Pure-stdlib (no external deps). Handles dotted numeric versions plus letter
    suffixes like OpenSSL's '1.0.1g'. Strips epochs / distro release / build
    metadata first (e.g. '1:2.4.49-1ubuntu1' -> '2.4.49'). Returns None if the
    string has no usable numeric version (so we never match on garbage).
    """
    if not v or v in ("*", "-"):
        return None
    v = str(v).split(":")[-1].split("-")[0].split("+")[0].split("~")[0].strip()
    m = re.match(r"[0-9][0-9a-zA-Z.]*", v)
    if not m:
        return None
    core = m.group(0)
    out = []
    for part in core.split("."):
        pm = re.match(r"(\d+)([a-zA-Z]*)", part)
        if pm:
            out.append((int(pm.group(1)), pm.group(2)))
        else:
            out.append((-1, part))
    return tuple(out) or None


def _is_kernel_pkg(name: str) -> bool:
    """True for the actual Linux-kernel package, which NVD lists under the product
    `linux_kernel` ("linux kernel" normalized) but distros package under a different
    name: `kernel`/`kernel-core`/`kernel-modules…` (RHEL/Fedora/SUSE) or
    `linux-image-*`/`linux-headers-*` (Debian/Ubuntu). Deliberately strict so unrelated
    `linux-*` packages (e.g. linux-sysctl-defaults, linux-firmware) are NOT mis-mapped.
    """
    n = _normalize(name)  # hyphens/underscores -> spaces, lowercased
    return (n == "kernel" or n.startswith("kernel ")
            or n.startswith("linux image") or n.startswith("linux headers"))


def _product_tokens(service: Service) -> set:
    """Normalized product names for the service (product, CPE product, service name)."""
    tokens = set()
    for raw in (service.product, service.service_name):
        n = _normalize(raw)
        if n:
            tokens.add(n)
            first = n.split()[0]
            if len(first) >= 3:
                tokens.add(first)
    if service.cpe:
        body = service.cpe.replace("cpe:2.3:", "").replace("cpe:/", "")
        parts = body.split(":")
        if len(parts) > 2:
            p = _normalize(parts[2].replace("_", " "))
            if p:
                tokens.add(p)
                tokens.add(p.split()[0])
    # Map the kernel package name to NVD's `linux_kernel` product so kernel CVEs match.
    if _is_kernel_pkg(service.product) or _is_kernel_pkg(service.service_name):
        tokens.add("linux kernel")
    return {t for t in tokens if len(t) >= 3}


def _product_matches(pkg_tokens: set, entry_product: str) -> bool:
    """Require the FULL CVE product name to equal one of the package tokens.

    pkg_tokens already includes the package's full normalized name AND its first
    word, so 'openssh-server' (tokens {"openssh server", "openssh"}) still matches a
    CVE whose product is 'openssh'. But it will NOT match multi-word products like
    'openssl-feedstock', 'dbus-broker', 'apt-cacher-ng' or 'linux kernel' — which
    were the main false-positive source from first-word matching.
    """
    ep = _normalize(entry_product)
    return bool(ep) and ep in pkg_tokens


def _in_range(version: tuple, e: dict) -> bool:
    """Is `version` inside the affected range described by entry `e`?"""
    if "v" in e:  # exact affected version
        ev = _parse_version(e["v"])
        return ev is not None and version == ev
    bounded = False
    if "vs" in e:
        s = _parse_version(e["vs"])
        if s is None:
            return False
        if not (version >= s if e.get("vsi") else version > s):
            return False
        bounded = True
    if "ve" in e:
        en = _parse_version(e["ve"])
        if en is None:
            return False
        if not (version <= en if e.get("vei") else version < en):
            return False
        bounded = True
    return bounded  # product-only (no bounds) is NOT a confident match


def _fix_hint(e: dict) -> str:
    if "ve" in e:
        return (f"upgrade to a release after {e['ve']}" if e.get("vei")
                else f"upgrade to {e['ve']} or later")
    if "v" in e:
        return f"upgrade to a version other than {e['v']}"
    return "apply the vendor security update"


def correlate_service(db: Session, service: Service, max_per_service: int = 100):
    """Return [(cve, confidence, reason)] for one service via precise version matching."""
    results = []
    version = _parse_version(service.version)
    if version is None:
        return results  # no usable version -> no confident correlation
    tokens = _product_tokens(service)
    if not tokens:
        return results

    # Candidate query: product-name index contains one of our product tokens.
    likes = [CVE.cpe_products.ilike(f"%{t}%") for t in tokens if len(t) >= 3]
    if not likes:
        return results
    candidates = db.query(CVE).filter(or_(*likes)).limit(3000).all()

    seen = set()
    for cve in candidates:
        if not cve.affected:
            continue
        try:
            entries = json.loads(cve.affected)
        except (ValueError, TypeError):
            continue
        for e in entries:
            if not _product_matches(tokens, e.get("p", "")):
                continue
            if _in_range(version, e):
                if cve.cve_id in seen:
                    break
                seen.add(cve.cve_id)
                reason = f"{e.get('p')} {service.version or version} affected — {_fix_hint(e)}"
                fix_ver = e.get("ve") or e.get("v") or ""   # the version that fixes it
                results.append((cve, "high", reason, fix_ver))
                break
        if len(results) >= max_per_service:
            break

    results.sort(key=lambda r: (_SEV_WEIGHT.get(r[0].severity, 0), r[0].cvss_v3_score or 0),
                 reverse=True)
    return results


def latest_fix_version(fix_versions) -> str:
    """Return the highest version string among candidate fixes (upgrading to it
    resolves all the lower-versioned CVEs). Empty string if none are usable."""
    best, best_v = "", None
    for fv in fix_versions:
        pv = _parse_version(fv)
        if pv is not None and (best_v is None or pv > best_v):
            best_v, best = pv, fv
    return best


def correlate_package(db: Session, name: str, version: str):
    """Correlate an installed package (name + version) against the CVE DB."""
    transient = Service(
        port=0, protocol="pkg", state="installed",
        service_name=name, product=name, version=version, cpe="",
    )
    return correlate_service(db, transient, max_per_service=60)
