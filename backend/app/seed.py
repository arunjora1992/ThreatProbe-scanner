"""Idempotent bootstrap: create the admin user and seed a few well-known CVEs.

The sample CVEs let an operator exercise correlation/reporting immediately in an
air-gapped environment before importing full NVD feeds. Re-running is safe.
"""
from datetime import datetime

from .auth import hash_password
from .config import settings
from .database import SessionLocal
from .models import CVE, User

SAMPLE_CVES = [
    {
        "cve_id": "CVE-2021-44228", "description":
        "Apache Log4j2 JNDI features used in configuration, log messages, and parameters "
        "do not protect against attacker-controlled LDAP and other JNDI related endpoints "
        "(Log4Shell). Allows remote code execution.",
        "cvss_v3_score": 10.0, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL", "cpe_products": "apache:log4j:2.14.1|apache:log4j:2.0",
        "references": "https://logging.apache.org/log4j/2.x/security.html",
        "remediation": "Upgrade Log4j2 to 2.17.1 or later. Remove the JndiLookup class where upgrade is not possible.",
        "cwe": "CWE-502",
    },
    {
        "cve_id": "CVE-2021-41773", "description":
        "A path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49 "
        "allows attackers to map URLs to files outside the document root and can lead to RCE.",
        "cvss_v3_score": 7.5, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH", "cpe_products": "apache:http_server:2.4.49",
        "references": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "remediation": "Upgrade Apache HTTP Server to 2.4.51 or later.",
        "cwe": "CWE-22",
    },
    {
        "cve_id": "CVE-2014-0160", "description":
        "The TLS heartbeat extension in OpenSSL 1.0.1 before 1.0.1g (Heartbleed) allows "
        "remote attackers to read process memory and obtain sensitive information.",
        "cvss_v3_score": 7.5, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH", "cpe_products": "openssl:openssl:1.0.1",
        "references": "https://www.openssl.org/news/secadv/20140407.txt",
        "remediation": "Upgrade OpenSSL to 1.0.1g or later and reissue/revoke affected certificates.",
        "cwe": "CWE-125",
    },
    {
        "cve_id": "CVE-2017-0144", "description":
        "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary "
        "code via crafted packets (EternalBlue).",
        "cvss_v3_score": 8.1, "cvss_v3_vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "cpe_products": "microsoft:windows:smbv1|microsoft:smb:1.0",
        "references": "https://learn.microsoft.com/security-updates/securitybulletins/2017/ms17-010",
        "remediation": "Apply MS17-010. Disable SMBv1. Restrict SMB at the network perimeter.",
        "cwe": "CWE-20",
    },
    {
        "cve_id": "CVE-2018-15473", "description":
        "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to timing "
        "differences when authenticating non-existent vs existing users.",
        "cvss_v3_score": 5.3, "cvss_v3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "MEDIUM", "cpe_products": "openbsd:openssh:7.7",
        "references": "https://www.openssh.com/txt/release-7.8",
        "remediation": "Upgrade OpenSSH to 7.8 or later.",
        "cwe": "CWE-200",
    },
    {
        "cve_id": "CVE-2019-0211", "description":
        "Apache HTTP Server 2.4.17 to 2.4.38 privilege escalation from modules' scripts: "
        "code executing in a less-privileged child process could execute arbitrary code "
        "with the privileges of the parent process.",
        "cvss_v3_score": 7.8, "cvss_v3_vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "HIGH", "cpe_products": "apache:http_server:2.4.38|apache:http_server:2.4.17",
        "references": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "remediation": "Upgrade Apache HTTP Server to 2.4.39 or later.",
        "cwe": "CWE-264",
    },
    {
        "cve_id": "CVE-2020-1938", "description":
        "Apache Tomcat AJP Connector (Ghostcat) allows reading or including files in the "
        "web application via a crafted AJP request, potentially leading to RCE.",
        "cvss_v3_score": 9.8, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "cpe_products": "apache:tomcat:9.0.30|apache:tomcat:8.5.50",
        "references": "https://tomcat.apache.org/security-9.html",
        "remediation": "Upgrade Tomcat and disable/secure the AJP connector if unused.",
        "cwe": "CWE-269",
    },
    {
        "cve_id": "CVE-2022-22965", "description":
        "Spring Framework RCE via data binding (Spring4Shell) on JDK 9+ when deployed as a "
        "WAR on Apache Tomcat.",
        "cvss_v3_score": 9.8, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "cpe_products": "vmware:spring_framework:5.3.0|pivotal:spring_framework:5.2.0",
        "references": "https://spring.io/security/cve-2022-22965",
        "remediation": "Upgrade Spring Framework to 5.3.18 / 5.2.20 or later.",
        "cwe": "CWE-94",
    },
    {
        "cve_id": "CVE-2014-6271", "description":
        "GNU Bash through 4.3 processes trailing strings after function definitions in "
        "environment variables (Shellshock), allowing remote code execution via CGI and other vectors.",
        "cvss_v3_score": 9.8, "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL", "cpe_products": "gnu:bash:4.3",
        "references": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        "remediation": "Patch Bash to the fixed package version provided by your distribution.",
        "cwe": "CWE-78",
    },
    {
        "cve_id": "CVE-2017-5638", "description":
        "Apache Struts 2 Jakarta Multipart parser RCE via crafted Content-Type header.",
        "cvss_v3_score": 10.0, "cvss_v3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "CRITICAL", "cpe_products": "apache:struts:2.5.10|apache:struts:2.3.31",
        "references": "https://cwiki.apache.org/confluence/display/WW/S2-045",
        "remediation": "Upgrade Apache Struts to 2.3.32 / 2.5.10.1 or later.",
        "cwe": "CWE-20",
    },
]


def run_seed():
    db = SessionLocal()
    try:
        # Admin user
        if not db.query(User).filter(User.username == settings.admin_username).first():
            db.add(User(
                username=settings.admin_username,
                hashed_password=hash_password(settings.admin_password),
                role="admin",
            ))
            db.commit()
            print(f"[seed] created admin user '{settings.admin_username}'", flush=True)

        # Sample CVEs (only if the table is empty, to avoid clobbering imported feeds)
        if db.query(CVE).count() == 0:
            import json as _json
            for rec in SAMPLE_CVES:
                rec = dict(rec)
                rec.setdefault("published", datetime(2021, 1, 1))
                rec.setdefault("last_modified", datetime(2022, 1, 1))
                # Derive structured affected ranges from the "vendor:product:version" tokens
                # so the precise version-aware matcher works on the samples too.
                affected = []
                for tok in (rec.get("cpe_products") or "").split("|"):
                    bits = tok.split(":")
                    if len(bits) >= 3 and bits[2]:
                        affected.append({"p": bits[1].replace("_", " "),
                                         "ve": bits[2], "vei": True})
                rec["affected"] = _json.dumps(affected)
                db.add(CVE(**rec))
            db.commit()
            print(f"[seed] inserted {len(SAMPLE_CVES)} sample CVEs", flush=True)
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
