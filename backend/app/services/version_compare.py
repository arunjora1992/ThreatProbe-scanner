"""Distro package version comparison — RPM and dpkg (Debian) algorithms.

This is the correctness crux of backport-aware matching: deciding whether an installed
package version is older than the version a distro advisory says fixes a CVE. Distro
versions carry an epoch and a release (e.g. '0:5.14.0-427.el9'), so a naive string or
upstream-only compare is wrong. These implement the canonical rpm (`rpmvercmp`) and dpkg
version-ordering algorithms — stdlib only.
"""
import re

# ---------------------------------------------------------------------------
# RPM — rpmvercmp / labelCompare
# ---------------------------------------------------------------------------
_RPM_SEG = re.compile(r"(~|\^|[0-9]+|[a-zA-Z]+)")


def _rpm_segments(s):
    return _RPM_SEG.findall(s or "")


def rpm_vercmp(a: str, b: str) -> int:
    """Compare two RPM version (or release) strings. Returns -1/0/1."""
    if a == b:
        return 0
    sa, sb = _rpm_segments(a), _rpm_segments(b)
    i = 0
    while i < len(sa) or i < len(sb):
        # '~' (tilde) sorts BEFORE everything, including the empty string (pre-release).
        at = sa[i] if i < len(sa) else None
        bt = sb[i] if i < len(sb) else None
        if at == "~" or bt == "~":
            if at != "~":
                return 1
            if bt != "~":
                return -1
            i += 1
            continue
        # '^' sorts after the (shorter) string end but before a continuing segment.
        if at == "^" or bt == "^":
            if at is None:
                return -1
            if bt is None:
                return 1
            if at != "^":
                return 1
            if bt != "^":
                return -1
            i += 1
            continue
        if at is None:
            return -1
        if bt is None:
            return 1
        a_num, b_num = at.isdigit(), bt.isdigit()
        if a_num and b_num:
            ai, bi = int(at), int(bt)
            if ai != bi:
                return -1 if ai < bi else 1
        elif a_num != b_num:
            # numeric segments are newer than alphabetic
            return 1 if a_num else -1
        else:
            if at != bt:
                return -1 if at < bt else 1
        i += 1
    return 0


def _split_evr(evr: str):
    """Split 'epoch:version-release' into (epoch:int, version, release)."""
    epoch = "0"
    rest = evr
    if ":" in rest:
        epoch, rest = rest.split(":", 1)
        epoch = epoch.strip() or "0"
    version = rest
    release = ""
    if "-" in rest:
        version, release = rest.rsplit("-", 1)
    try:
        ep = int(epoch)
    except ValueError:
        ep = 0
    return ep, version, release


def rpm_evr_cmp(a: str, b: str) -> int:
    """Compare full RPM EVR strings ('[epoch:]version[-release]'). Returns -1/0/1."""
    ea, va, ra = _split_evr(a)
    eb, vb, rb = _split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = rpm_vercmp(va, vb)
    if c:
        return c
    return rpm_vercmp(ra, rb)


# ---------------------------------------------------------------------------
# dpkg (Debian) version comparison
# ---------------------------------------------------------------------------
def _dpkg_order(ch: str) -> int:
    """dpkg character ordering: '~' < '' < letters < everything else (by codepoint)."""
    if ch == "~":
        return -1
    if ch == "":
        return 0
    if ch.isalpha():
        return ord(ch)
    return ord(ch) + 256  # non-letters sort after letters


def _dpkg_cmp_part(a: str, b: str) -> int:
    """Compare one dpkg part (upstream or revision) by the Debian algorithm."""
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        # non-digit run, compared by special ordering
        first_diff = 0
        while (ia < len(a) and not a[ia].isdigit()) or (ib < len(b) and not b[ib].isdigit()):
            ca = a[ia] if ia < len(a) and not a[ia].isdigit() else ""
            cb = b[ib] if ib < len(b) and not b[ib].isdigit() else ""
            oa, ob = _dpkg_order(ca), _dpkg_order(cb)
            if oa != ob:
                return -1 if oa < ob else 1
            if ca:
                ia += 1
            if cb:
                ib += 1
        # digit run, compared numerically (leading zeros ignored)
        na = ""
        while ia < len(a) and a[ia].isdigit():
            na += a[ia]; ia += 1
        nb = ""
        while ib < len(b) and b[ib].isdigit():
            nb += b[ib]; ib += 1
        va, vb = int(na or "0"), int(nb or "0")
        if va != vb:
            return -1 if va < vb else 1
    return 0


def dpkg_vercmp(a: str, b: str) -> int:
    """Compare two full dpkg versions ('[epoch:]upstream[-revision]'). Returns -1/0/1."""
    if a == b:
        return 0
    # epoch
    ea, ra = ("0", a)
    if ":" in a:
        ea, ra = a.split(":", 1)
    eb, rb = ("0", b)
    if ":" in b:
        eb, rb = b.split(":", 1)
    try:
        if int(ea or 0) != int(eb or 0):
            return -1 if int(ea or 0) < int(eb or 0) else 1
    except ValueError:
        pass
    # upstream-revision
    ua, sep, va = ra.rpartition("-")
    if not sep:  # no revision
        ua, va = ra, ""
    ub, sep, vb = rb.rpartition("-")
    if not sep:
        ub, vb = rb, ""
    c = _dpkg_cmp_part(ua, ub)
    if c:
        return c
    return _dpkg_cmp_part(va, vb)


def compare(manager: str, a: str, b: str) -> int:
    """Compare versions a,b using the given package manager's algorithm. Returns -1/0/1."""
    if manager == "dpkg":
        return dpkg_vercmp(a, b)
    return rpm_evr_cmp(a, b)  # rpm default


def is_vulnerable(manager: str, installed: str, fixed: str) -> bool:
    """True if `installed` is older than `fixed` (i.e. the fix is not yet applied)."""
    if not fixed:
        return True  # advisory with no fix version => still vulnerable / no patch available
    if not installed:
        return False
    try:
        return compare(manager, installed, fixed) < 0
    except Exception:  # noqa: BLE001 - never let a malformed version crash a scan
        return False
