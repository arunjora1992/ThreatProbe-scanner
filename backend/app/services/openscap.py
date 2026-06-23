"""Full CIS-benchmark compliance scanning via OpenSCAP + SCAP Security Guide (SSG).

When a credentialed target has `oscap` (openscap-scanner) and SSG content installed,
we run the *official* CIS profile for that OS and import every rule result — the real,
auditor-accepted benchmark (hundreds of numbered controls) with a compliance score,
rather than our hand-written subset. If oscap/SSG isn't present the caller falls back to
the built-in hardening checks (services/hardening.py).

Everything runs over the existing read-only SSH session: locate the SSG datastream,
pick the CIS profile, `oscap xccdf eval --results <tmp>`, read the results XML back,
parse it namespace-agnostically, then remove the temp file. Nothing else is changed on
the target (oscap evaluation is read-only).
"""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, List, Optional

from .hardening import HardeningResult

SSG_DIR = "/usr/share/xml/scap/ssg/content"
_RESULTS_PATH = "/tmp/.threatprobe-oscap-results.xml"

_SEV_MAP = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "unknown": "MEDIUM"}


@dataclass
class OpenScapResult:
    available: bool = False
    profile: str = ""
    datastream: str = ""
    score: Optional[float] = None
    results: List[HardeningResult] = None


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def oscap_available(ex: Callable[[str], str]) -> bool:
    return "oscap" in ex("command -v oscap 2>/dev/null").strip()


def find_datastream(ex: Callable[[str], str], os_id: str, version_id: str) -> str:
    """Pick the SSG datastream best matching the target OS, or '' if none found."""
    listing = ex(f"ls -1 {SSG_DIR}/ssg-*-ds.xml 2>/dev/null")
    files = [ln.strip() for ln in listing.splitlines() if ln.strip().endswith("-ds.xml")]
    if not files:
        return ""
    oid = (os_id or "").lower()
    major = (version_id or "").split(".")[0]
    compact = (version_id or "").replace(".", "")
    # RHEL-family clones map to the rhel datastream.
    family = "rhel" if oid in ("centos", "rocky", "almalinux", "ol", "oraclelinux", "rhel") else oid
    candidates = [f"ssg-{oid}{major}-ds.xml", f"ssg-{family}{major}-ds.xml",
                  f"ssg-{oid}{compact}-ds.xml", f"ssg-{family}{compact}-ds.xml"]
    for cand in candidates:
        for f in files:
            if f.endswith("/" + cand) or f.endswith(cand):
                return f
    return files[0] if len(files) == 1 else ""


def find_cis_profile(ex: Callable[[str], str], datastream: str, prefer: str = "") -> str:
    """Return the best CIS profile id in the datastream (preferring a configured one)."""
    out = ex(f"oscap info --profiles {datastream} 2>/dev/null")
    # Lines look like: xccdf_org.ssgproject.content_profile_cis:CIS ... Benchmark
    ids = [ln.split(":", 1)[0].strip() for ln in out.splitlines() if ln.strip()]
    if not ids:
        return ""
    if prefer:
        for pid in ids:
            if prefer in pid:
                return pid
    cis = [p for p in ids if "cis" in p.lower()]
    if not cis:
        return ""
    # Prefer a Level 1 server profile, else plain cis, else first CIS profile.
    for needle in ("cis_server_l1", "_cis_server_l1", "cis_level1_server", "_cis\Z", "cis"):
        for pid in cis:
            if re.search(needle, pid.lower()):
                return pid
    return cis[0]


def parse_results(xml_text: str) -> "tuple[Optional[float], List[HardeningResult]]":
    """Parse an XCCDF results document into (score, [HardeningResult]) — namespace-agnostic."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None, []

    # Rule definitions: id -> (title, severity, fixtext)
    rules = {}
    for el in root.iter():
        if _localname(el.tag) != "Rule":
            continue
        rid = el.get("id", "")
        if not rid:
            continue
        title = severity = fixtext = ""
        severity = el.get("severity", "") or ""
        for child in el:
            ln = _localname(child.tag)
            if ln == "title" and not title:
                title = "".join(child.itertext()).strip()
            elif ln == "fixtext" and not fixtext:
                fixtext = "".join(child.itertext()).strip()
        rules[rid] = (title, severity.lower(), fixtext)

    score = None
    results: List[HardeningResult] = []
    for el in root.iter():
        ln = _localname(el.tag)
        if ln == "score" and score is None:
            try:
                score = float((el.text or "").strip())
            except ValueError:
                pass
        elif ln == "rule-result":
            rid = el.get("idref", "")
            res = sev_attr = ""
            ident = ""
            for child in el:
                cln = _localname(child.tag)
                if cln == "result":
                    res = (child.text or "").strip().lower()
                elif cln == "ident" and not ident:
                    ident = (child.text or "").strip()
            sev_attr = el.get("severity", "")
            title, rsev, fixtext = rules.get(rid, ("", "", ""))
            sev = _SEV_MAP.get((sev_attr or rsev or "unknown").lower(), "MEDIUM")
            short = rid.split("content_rule_")[-1] if "content_rule_" in rid else rid
            if res == "fail":
                status = "fail"
            elif res == "pass":
                status = "pass"
            elif res in ("error", "unknown"):
                status = "error"
            else:
                # notapplicable / notchecked / notselected / informational — skip noise
                continue
            results.append(HardeningResult(
                check_id=short[:64], title=(title or short)[:255],
                severity=(sev if status == "fail" else "INFO"), status=status,
                detail=(title or "")[:1000],
                remediation=(fixtext[:1500] if status == "fail" else ""),
                evidence=ident))
    return score, results


def run(ex: Callable[[str], str], os_id: str, version_id: str,
        prefer_profile: str = "") -> OpenScapResult:
    """Run the official CIS profile via oscap. Returns available=False to trigger fallback."""
    if not oscap_available(ex):
        return OpenScapResult(available=False)
    ds = find_datastream(ex, os_id, version_id)
    if not ds:
        return OpenScapResult(available=False)
    profile = find_cis_profile(ex, ds, prefer_profile)
    if not profile:
        return OpenScapResult(available=False)
    # eval returns 0 (all pass) or 2 (some failed) on success; both are fine.
    ex(f"oscap xccdf eval --profile {profile} --results {_RESULTS_PATH} {ds} "
       f">/dev/null 2>&1; true")
    xml_text = ex(f"cat {_RESULTS_PATH} 2>/dev/null")
    ex(f"rm -f {_RESULTS_PATH} 2>/dev/null; true")
    if not xml_text.strip():
        return OpenScapResult(available=False)
    score, results = parse_results(xml_text)
    if not results:
        return OpenScapResult(available=False)
    return OpenScapResult(available=True, profile=profile, datastream=ds.split("/")[-1],
                          score=score, results=results)
