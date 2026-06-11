# CVE feed import directory

Place NVD JSON feed files here, then click **Import NVD feeds** in the GUI
(CVE Database page) or call `POST /api/cves/import`.

## Supported formats
- **NVD 1.1 legacy feeds** — `nvdcve-1.1-YYYY.json` or `.json.gz`
  Download (on an internet-connected machine) from:
  `https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz`
- **NVD 2.0 API exports** — JSON containing a `vulnerabilities` array.
- Both `.json` and `.json.gz` are accepted.

## Air-gapped workflow
1. On a connected machine, download the yearly feed files.
2. Copy them onto media and transfer into this directory on the air-gapped host.
3. Run the import from the GUI. Re-importing updates existing records.

Until you import feeds, the platform ships with a small set of well-known sample
CVEs (Log4Shell, Heartbleed, EternalBlue, etc.) so correlation and reporting work
out of the box.
