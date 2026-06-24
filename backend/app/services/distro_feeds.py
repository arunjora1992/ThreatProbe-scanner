"""Distro security-advisory feeds for backport-aware package matching.

Ingests vendor advisory data so the credentialed package audit can use the distro's
*fixed version* instead of raw NVD upstream ranges (which over-report because distros
backport fixes onto a base version). Supported, air-gap-friendly formats dropped in the
feed directory:

  * OVAL v2 (XML, optionally .bz2/.gz/.xz) — Red Hat (RHEL/CentOS), Oracle Linux (ELSA),
    Rocky/Alma, and Ubuntu all publish OVAL. One generic parser handles them; the
    distro + release are read from each definition's <affected><platform>.
  * Debian Security Tracker JSON (single file) — package -> cve -> release -> fix.

Each parsed row -> DistroAdvisory(distro, release, package, cve_id, fixed_version, …).
Matching is EVR-aware (services/version_compare). When no advisories are loaded for a
host's distro, the caller falls back to NVD matching.
"""
import bz2
import glob
import gzip
import json
import lzma
import os
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from ..config import settings
from ..models import DistroAdvisory
from . import version_compare

# os-release ID -> (canonical distro key, package manager)
_OS_ID_MAP = {
    "rhel": ("rhel", "rpm"), "centos": ("centos", "rpm"), "rocky": ("rocky", "rpm"),
    "almalinux": ("alma", "rpm"), "alma": ("alma", "rpm"),
    "ol": ("oracle", "rpm"), "oraclelinux": ("oracle", "rpm"),
    "fedora": ("fedora", "rpm"), "sles": ("suse", "rpm"), "opensuse-leap": ("suse", "rpm"),
    "ubuntu": ("ubuntu", "dpkg"), "debian": ("debian", "dpkg"),
}

# RHEL-family clones resolve to Red Hat advisory data when their own isn't loaded.
_RHEL_FAMILY = {"rhel", "centos", "rocky", "alma", "oracle"}


def distro_key(os_id: str) -> Tuple[str, str]:
    """Map an os-release ID to (distro key, manager). Unknown -> ('', 'rpm')."""
    return _OS_ID_MAP.get((os_id or "").lower(), ("", "rpm"))


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


_PLATFORM_RE = re.compile(
    r"(red hat enterprise linux|centos|rocky|almalinux|alma|oracle linux|"
    r"ubuntu|debian|sles|suse|opensuse)\D*(\d+(?:\.\d+)?)", re.I)


def _platform_to_distro(platform: str) -> Tuple[str, str, str]:
    """'Red Hat Enterprise Linux 9' -> ('rhel','9','rpm'); '' if unrecognized."""
    m = _PLATFORM_RE.search(platform or "")
    if not m:
        return "", "", ""
    name, ver = m.group(1).lower(), m.group(2)
    if "red hat" in name:
        return "rhel", ver, "rpm"
    if "oracle" in name:
        return "oracle", ver, "rpm"
    if name in ("sles", "suse", "opensuse"):
        return "suse", ver, "rpm"
    if name in ("centos", "rocky", "alma", "almalinux"):
        return ("alma" if name == "almalinux" else name), ver, "rpm"
    if name == "ubuntu":
        return "ubuntu", ver, "dpkg"
    if name == "debian":
        return "debian", ver, "dpkg"
    return "", "", ""


def _open(path: str):
    if path.endswith(".bz2"):
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def parse_oval(xml_text: str) -> List[dict]:
    """Parse OVAL v2 into advisory rows. Namespace-agnostic; handles rpm + dpkg OVAL."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    objects: Dict[str, str] = {}     # object_id -> package name
    states: Dict[str, str] = {}      # state_id  -> fixed evr (only "less than" ops)
    tests: Dict[str, Tuple[str, str]] = {}  # test_id -> (object_ref, state_ref)
    variables: Dict[str, str] = {}   # var_id -> literal value (Ubuntu names/evr via var_ref)

    def _val_or_var(child) -> str:
        """A child's literal text, or its var_ref's resolved value (filled in pass 2)."""
        txt = (child.text or "").strip()
        if txt:
            return txt
        ref = child.get("var_ref")
        return variables.get(ref, "") if ref else ""

    # Pass 1: collect constant_variable values (Ubuntu stores package names / evr here).
    for el in root.iter():
        ln = _localname(el.tag)
        if ln == "constant_variable":
            vid = el.get("id", "")
            for child in el:
                if _localname(child.tag) == "value" and (child.text or "").strip():
                    variables[vid] = child.text.strip()
                    break

    # Pass 2: objects, states, tests (resolving var_ref against the variable map).
    for el in root.iter():
        ln = _localname(el.tag)
        if ln.endswith("_object"):
            oid = el.get("id", "")
            for child in el:
                if _localname(child.tag) == "name":
                    name = _val_or_var(child)
                    if name:
                        objects[oid] = name
                    break
        elif ln.endswith("_state"):
            sid = el.get("id", "")
            for child in el:
                cln = _localname(child.tag)
                if cln in ("evr", "version") and "less than" in (child.get("operation") or ""):
                    states[sid] = _val_or_var(child)
                    break
        elif ln.endswith("_test"):
            tid = el.get("id", "")
            obj_ref = state_ref = ""
            for child in el:
                cln = _localname(child.tag)
                if cln == "object":
                    obj_ref = child.get("object_ref", "")
                elif cln == "state":
                    state_ref = child.get("state_ref", "")
            if tid and obj_ref:
                tests[tid] = (obj_ref, state_ref)

    # Index every definition: its own test_refs, the definitions it extends, and
    # (for CVE definitions) its metadata. Ubuntu puts the dpkginfo tests in per-package
    # definitions referenced from the CVE definition via <extend_definition>; RHEL/Oracle
    # inline the tests. Resolving extends transitively handles both.
    defs = {}            # def_id -> {"tests": set, "extends": set}
    cve_defs = []        # definitions that carry CVE references
    for defin in root.iter():
        if _localname(defin.tag) != "definition":
            continue
        did = defin.get("id", "")
        own_tests, extends = set(), set()
        cves, severity, advisory_id, platform = [], "", "", ""
        for el in defin.iter():
            ln = _localname(el.tag)
            if ln == "criterion":
                tref = el.get("test_ref", "")
                if tref:
                    own_tests.add(tref)
            elif ln == "extend_definition":
                dref = el.get("definition_ref", "")
                if dref:
                    extends.add(dref)
            elif ln == "reference" and (el.get("source") or "").upper() == "CVE":
                if el.get("ref_id"):
                    cves.append(el.get("ref_id"))
            elif ln == "severity" and not severity:
                severity = (el.text or "").strip()
            elif ln == "platform" and not platform:
                platform = (el.text or "").strip()
            elif ln == "title" and not advisory_id:
                m = re.search(r"\b([RES]HSA|ELSA|USN|DSA|DLA)[-: ]?\d[\w:-]*", el.text or "")
                if m:
                    advisory_id = m.group(0)
        defs[did] = {"tests": own_tests, "extends": extends}
        if cves:
            cve_defs.append((did, cves, severity, advisory_id, platform))

    def _all_tests(def_id, seen):
        """Test refs of a definition plus every definition it extends (transitive)."""
        if def_id in seen or def_id not in defs:
            return set()
        seen.add(def_id)
        out = set(defs[def_id]["tests"])
        for ext in defs[def_id]["extends"]:
            out |= _all_tests(ext, seen)
        return out

    rows = []
    for did, cves, severity, advisory_id, platform in cve_defs:
        distro, release, manager = _platform_to_distro(platform)
        if not distro:
            continue
        pkgfix = {}
        for tref in _all_tests(did, set()):
            if tref in tests:
                obj_ref, state_ref = tests[tref]
                pkg = objects.get(obj_ref)
                if pkg:
                    pkgfix[pkg] = states.get(state_ref, "")  # "" = no fix evr
        for pkg, fixed in pkgfix.items():
            for cve in cves:
                rows.append({
                    "distro": distro, "release": release, "package": pkg.lower(),
                    "cve_id": cve, "fixed_version": fixed, "severity": severity,
                    "advisory_id": advisory_id, "manager": manager,
                })
    return rows


def parse_debian_json(data: dict) -> List[dict]:
    """Parse the Debian Security Tracker JSON (package -> cve -> releases -> fix)."""
    rows = []
    for pkg, cves in (data or {}).items():
        if not isinstance(cves, dict):
            continue
        for cve, info in cves.items():
            if not cve.startswith("CVE"):
                continue
            releases = (info or {}).get("releases", {})
            for rel, rinfo in releases.items():
                status = (rinfo or {}).get("status", "")
                fixed = (rinfo or {}).get("fixed_version", "") or ""
                if status == "resolved" and fixed and fixed != "0":
                    rows.append({"distro": "debian", "release": rel, "package": pkg.lower(),
                                 "cve_id": cve, "fixed_version": fixed,
                                 "severity": (rinfo or {}).get("urgency", ""),
                                 "advisory_id": "", "manager": "dpkg"})
                elif status == "open":
                    rows.append({"distro": "debian", "release": rel, "package": pkg.lower(),
                                 "cve_id": cve, "fixed_version": "",
                                 "severity": (rinfo or {}).get("urgency", ""),
                                 "advisory_id": "", "manager": "dpkg"})
    return rows


def _rows_from_file(path: str) -> List[dict]:
    with _open(path) as fh:
        head = fh.read(4096)
        fh.seek(0)
        if head.lstrip().startswith("{"):  # JSON (Debian tracker)
            return parse_debian_json(json.load(fh))
        return parse_oval(fh.read())


def _upsert(db: Session, rows: List[dict]) -> int:
    if not rows:
        return 0
    n = 0
    # de-dup within the batch on the unique key
    seen = {}
    for r in rows:
        seen[(r["distro"], r["release"], r["package"], r["cve_id"])] = r
    keys = list(seen)
    for i in range(0, len(keys), 1000):
        chunk = keys[i:i + 1000]
        existing = {
            (a.distro, a.release, a.package, a.cve_id): a
            for a in db.query(DistroAdvisory).filter(
                DistroAdvisory.cve_id.in_([k[3] for k in chunk])).all()
        }
        for k in chunk:
            r = seen[k]
            row = existing.get(k)
            if row:
                row.fixed_version = r["fixed_version"]
                row.severity = r["severity"]
                row.advisory_id = r["advisory_id"]
                row.manager = r["manager"]
            else:
                db.add(DistroAdvisory(**r))
            n += 1
        db.commit()
    return n


def import_distro_feeds(db: Session, directory: Optional[str] = None) -> dict:
    """Import every OVAL/Debian-JSON advisory feed found under <feed_dir>/distro_feeds."""
    directory = directory or os.path.join(settings.cve_feed_dir, "distro_feeds")
    if not os.path.isdir(directory):
        return {"imported": 0, "files": 0,
                "message": f"No distro-feed directory at {directory}. Create it and drop "
                           "vendor OVAL (.xml/.bz2) or the Debian tracker JSON there."}
    patterns = ["*.oval.xml", "*.xml", "*.xml.bz2", "*.xml.gz", "*.xml.xz",
                "*.json", "*.json.gz", "*.json.bz2"]
    paths = sorted({p for pat in patterns for p in glob.glob(os.path.join(directory, pat))})
    total = files = 0
    by_distro: Dict[str, int] = {}
    for path in paths:
        try:
            rows = _rows_from_file(path)
        except Exception:  # noqa: BLE001 - skip an unreadable/невalid feed, keep going
            continue
        if not rows:
            continue
        total += _upsert(db, rows)
        files += 1
        for r in rows:
            by_distro[r["distro"]] = by_distro.get(r["distro"], 0) + 1
    summary = ", ".join(f"{k}:{v}" for k, v in sorted(by_distro.items()))
    return {"imported": total, "files": files,
            "message": (f"Imported {total} advisory rows from {files} feed file(s) "
                        f"({summary})." if files else
                        f"No advisory feeds found in {directory}.")}


def has_advisories(db: Session, distro: str) -> bool:
    candidates = [distro]
    if distro in _RHEL_FAMILY:
        candidates.append("rhel")  # clones fall back to Red Hat data
    return db.query(DistroAdvisory.id).filter(
        DistroAdvisory.distro.in_(candidates)).first() is not None


def correlate_distro(db: Session, distro: str, release: str, manager: str,
                     package: str, full_version: str) -> List[dict]:
    """Return advisory matches for an installed package using EVR-aware comparison.

    Each match: {cve_id, fixed_version, severity, advisory_id, vulnerable: bool}. Only
    vulnerable matches are returned (installed < fixed, or no fix available).
    """
    candidates = [distro]
    if distro in _RHEL_FAMILY:
        candidates.append("rhel")
    q = db.query(DistroAdvisory).filter(
        DistroAdvisory.distro.in_(candidates),
        DistroAdvisory.package == (package or "").lower())
    rel_major = (release or "").split(".")[0]
    out, seen = [], set()
    for adv in q.all():
        # Release match: exact, or major-version match for rpm families ("9" vs "9.3").
        if adv.release and adv.release != release and adv.release.split(".")[0] != rel_major:
            continue
        if adv.cve_id in seen:
            continue
        if version_compare.is_vulnerable(adv.manager or manager, full_version, adv.fixed_version):
            seen.add(adv.cve_id)
            out.append({"cve_id": adv.cve_id, "fixed_version": adv.fixed_version,
                        "severity": adv.severity, "advisory_id": adv.advisory_id,
                        "vulnerable": True})
    return out
