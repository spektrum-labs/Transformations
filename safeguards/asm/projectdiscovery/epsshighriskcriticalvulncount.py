"""
Transformation: epssHighRiskCriticalVulnCount
Vendor: Project Discovery (Nuclei, run by Spektrum)  |  Category: Attack Surface Management
Evaluates: Count of live-matched findings whose CVE has an EPSS percentile at or above 0.95, within the
critical-severity scan. Its sibling epssHighRiskHighVulnCount reads the high-severity scan; together they cover
critical and high. Pass rule: count == 0. Each counted finding is listed in additionalFindings.

Input: the runParallelASMScan response the noCriticalFindings workflow already fetches (subfinder discovery of the
passport domain, then nuclei critical-severity templates across up to 25 discovered hosts). No extra scan, and no
network: EPSS comes from the finding itself. nuclei copies the template's classification block into every
ResultEvent (info.classification: cve-id, cvss-score, epss-score, epss-percentile), and the nuclei-templates
project stamps EPSS onto CVE templates. The values are the snapshot baked into the scanner image's templates,
not a live FIRST lookup.

Threshold 0.95: in the nuclei-templates tree EPSS percentile 0.95 is where the EPSS score crosses 0.10 (a 10%
modelled chance of exploitation in the next 30 days). 0.90 corresponds to a score near 0.04 and takes in 84% of
critical CVE templates, which would make this key a near-copy of criticalVulnerabilityCount.

Fails closed (None, reason in dataCollection.errors and transformation.errors): everything knownExploitedVulnCount
fails on (incomplete, empty, error-envelope, failed-host, truncated or capped-and-clean scans), and also a scan where
no finding reaches the threshold but some CVE finding carries no usable EPSS percentile, since that finding's risk is
unknown rather than low. A finding with no CVE (default login, exposure, takeover) has no EPSS by definition; it is
listed as not EPSS-scored and does not block the answer.

Unknown is never a measured answer: every return of None also sets dataCollection.status "error", which
Token-Service routes to isEvaluated false (Unevaluated, out of the score) instead of comparing None against
the requirement. That covers input that fails schema validation, a body that cannot be parsed, an unexpected
exception, a scan in which no host responded (domainsResponsive 0), a findings list holding an unreadable
entry, and a stored body whose scalars were stringified ("True", "25").
"""

import json
from datetime import datetime

CRITERIA_KEY = "epssHighRiskCriticalVulnCount"
SCAN_SCOPE = "critical"
EPSS_PERCENTILE_THRESHOLD = 0.95


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for step in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Project Discovery",
                "category": "Attack Surface Management"
            }
        }
    }


def is_true(value):
    """True for a real True and for the stringified forms a stored or replayed body carries ("True", "true")."""
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def scan_problem(data):
    """None when the scan completed across at least one host with no failed host, no error and an intact
    findings list; else the reason."""
    if not isinstance(data, dict):
        return "No scan data"
    domain = data.get("primaryDomain") or data.get("domain") or "unknown"
    status = data.get("status", "unknown")
    if status != "success" or is_true(data.get("error")):
        return "Nuclei scan status: " + str(status) + " for " + str(domain)
    scanned = to_int(data.get("domainsScanned"))
    if scanned is None or scanned <= 0:
        return "Nuclei scanned zero hosts for " + str(domain)
    templates = to_int(data.get("templatesScanned"))
    if templates is None or templates <= 0:
        return "Nuclei ran zero templates for " + str(domain)
    if "domainsResponsive" in data:
        responsive = to_int(data.get("domainsResponsive"))
        if responsive is None or responsive <= 0:
            return ("Nuclei reached no host of " + str(domain) + ": " + str(data.get("domainsUnresponsive"))
                    + " of " + str(scanned) + " unresponsive and the rest errored")
    failed = [r.get("domain", "unknown") for r in (data.get("domainResults") or [])
              if isinstance(r, dict) and r.get("status") not in ("success", "unresponsive")]
    errors = data.get("errors") or []
    if failed or errors:
        return "Nuclei scan failed for " + str(max(len(failed), len(errors))) + " host(s) of " + str(domain)
    findings = data.get("findings")
    if not isinstance(findings, list):
        return "Nuclei scan for " + str(domain) + " carries no findings list"
    if any(not isinstance(f, dict) for f in findings):
        return "Nuclei findings list for " + str(domain) + " holds an entry that is not a finding object"
    total = to_int(data.get("total"))
    if total is None or total != len(findings):
        return ("Nuclei findings list for " + str(domain) + " is truncated or inconsistent: " + str(len(findings))
                + " finding(s) against a total of " + str(data.get("total")))
    return None


def capped_note(data):
    """The reason a zero would be partial (more hosts discovered than scanned), else None."""
    if not is_true(data.get("domainsCapped")):
        return None
    scanned = to_int(data.get("domainsScanned"))
    discovered = to_int(data.get("totalDiscovered"))
    return ("Only " + str(scanned) + " of " + str(discovered) + " discovered host(s) of "
            + str(data.get("primaryDomain") or data.get("domain") or "unknown") + " were scanned")


def finding_info(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    return info if isinstance(info, dict) else {}


def finding_severity(finding):
    sev = finding_info(finding).get("severity")
    if not sev and isinstance(finding, dict):
        sev = finding.get("severity")
    return str(sev or "").strip().lower()


def finding_tags(finding):
    tags = finding_info(finding).get("tags")
    if isinstance(tags, str):
        tags = tags.split(",")
    if not isinstance(tags, list):
        return []
    return [str(t).strip().lower() for t in tags]


def finding_cves(finding):
    classification = finding_info(finding).get("classification")
    cves = classification.get("cve-id") if isinstance(classification, dict) else None
    if isinstance(cves, str):
        cves = cves.split(",")
    if not isinstance(cves, list):
        return []
    return [str(c).strip().upper() for c in cves if str(c).strip()]


def finding_name(finding):
    name = finding_info(finding).get("name")
    return str(name or finding.get("template-id") or "Unknown") if isinstance(finding, dict) else "Unknown"


def finding_where(finding):
    return str(finding.get("matched-at") or finding.get("host") or "unknown host")


def is_live_match(finding):
    """nuclei -jsonl only emits matches; a matcher-status of false (written under -ms) is not a finding."""
    return isinstance(finding, dict) and finding.get("matcher-status") is not False


def to_unit(value):
    """A probability-like number in [0, 1], else None (missing, non-numeric, negative or above 1)."""
    if isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if number != number or number < 0 or number > 1:
        return None
    return number


def finding_epss(finding):
    """(percentile, score) from info.classification; either may be None."""
    classification = finding_info(finding).get("classification")
    if not isinstance(classification, dict):
        return None, None
    return to_unit(classification.get("epss-percentile")), to_unit(classification.get("epss-score"))


def describe(finding, percentile, score):
    cves = finding_cves(finding)
    label = finding_name(finding) + (" (" + ", ".join(cves) + ")" if cves else "")
    epss = "EPSS percentile " + str(percentile) + (", score " + str(score) if score is not None else "")
    return "EPSS " + finding_severity(finding).upper() + ": " + label + " at " + finding_where(finding) + " [" + epss + "]"


def failed(reason, validation, summary):
    return create_response(result={CRITERIA_KEY: None}, validation=validation, api_errors=[reason],
                           transformation_errors=[reason], fail_reasons=[reason], input_summary=summary)


# --- evidenceItems (gap disputes) -----------------------------------------------------------------------
# Each offending finding becomes {fingerprint, kind, label, severity}. The fingerprint is the identity of the
# thing found, so a rescan with different counts or timestamps yields the same value and a new finding a new one:
#   fingerprint = sha256_hex(template-id + "|" + scheme://host[:port] + path)
# When a finding carries a matcher-name the template part is template-id + "#" + matcher-name, so two matchers of
# one template on one URL stay distinct; without a matcher-name the form above is unchanged.
# Normalisation of the finding's matched-at (host as a fallback): scheme and host lower-cased; userinfo, query
# string and fragment removed; the default port (80 for http, 443 for https) and a trailing dot on the host
# removed; trailing slashes removed from the path, so the root path is "" and https://h/ equals https://h; the
# path keeps its case and its percent-encoding. A value with no scheme gets the scheme "unknown". The sandbox
# allows no hashlib, so SHA-256 is implemented here; this block is identical in every ProjectDiscovery file and
# test_evidence_items.py checks it against hashlib.
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_hex(text):
    data = list(str(text).encode("utf-8"))
    bit_length = len(data) * 8
    data = data + [0x80]
    while len(data) % 64 != 56:
        data = data + [0]
    data = data + [(bit_length >> (8 * (7 - i))) & 0xff for i in range(8)]
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for start in range(0, len(data), 64):
        w = [(data[start + 4 * i] << 24) | (data[start + 4 * i + 1] << 16) | (data[start + 4 * i + 2] << 8)
             | data[start + 4 * i + 3] for i in range(16)]
        for i in range(16, 64):
            s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w = w + [(w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff]
        a, b, c, d, e, f, g, hh = h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
        for i in range(64):
            t1 = (hh + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ ((e ^ 0xffffffff) & g))
                  + SHA256_K[i] + w[i]) & 0xffffffff
            t2 = ((rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
            hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff
        h = [(h[0] + a) & 0xffffffff, (h[1] + b) & 0xffffffff, (h[2] + c) & 0xffffffff, (h[3] + d) & 0xffffffff,
             (h[4] + e) & 0xffffffff, (h[5] + f) & 0xffffffff, (h[6] + g) & 0xffffffff, (h[7] + hh) & 0xffffffff]
    digits = "0123456789abcdef"
    return "".join(["".join([digits[(word >> shift) & 15] for shift in (28, 24, 20, 16, 12, 8, 4, 0)]) for word in h])


def normalise_location(raw):
    """(scheme, host, path) of a nuclei matched-at / host value, normalised as described above."""
    text = str(raw or "").strip().split("#")[0].split("?")[0]
    scheme = "unknown"
    if "://" in text:
        scheme, text = text.split("://", 1)
        scheme = scheme.strip().lower() or "unknown"
    slash = text.find("/")
    authority = text if slash < 0 else text[:slash]
    path = "" if slash < 0 else text[slash:]
    authority = authority.split("@")[-1].strip().lower()
    port = ""
    if authority.startswith("["):
        close = authority.find("]")
        if close >= 0:
            port = authority[close + 2:] if authority[close + 1:close + 2] == ":" else ""
            authority = authority[:close + 1]
    elif ":" in authority:
        authority, port = authority.rsplit(":", 1)
    authority = authority.rstrip(".")
    if port and not ((scheme == "http" and port == "80") or (scheme == "https" and port == "443")):
        authority = authority + ":" + port
    return scheme, authority or "unknown", path.rstrip("/")


def evidence_item(finding):
    """One evidenceItems entry for an offending nuclei finding (see the block comment above)."""
    info = finding.get("info") if isinstance(finding.get("info"), dict) else {}
    template_id = str(finding.get("template-id") or info.get("name") or "unknown").strip()
    scheme, host, path = normalise_location(finding.get("matched-at") or finding.get("host"))
    sev = info.get("severity") or finding.get("severity")
    matcher = str(finding.get("matcher-name") or "").strip()
    if matcher:
        template_id = template_id + "#" + matcher
    return {"fingerprint": sha256_hex(template_id + "|" + scheme + "://" + host + path), "kind": "asm_finding",
            "label": template_id + " at " + host + path, "severity": str(sev or "").strip().lower()}


def evidence_items(findings):
    """Unique evidenceItems for the offending findings, ordered by fingerprint so scan order never matters."""
    seen = {}
    for finding in findings:
        if isinstance(finding, dict):
            item = evidence_item(finding)
            seen[item["fingerprint"]] = item
    return [seen[key] for key in sorted(seen.keys())]
# --- end evidenceItems -----------------------------------------------------------------------------------


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return failed("Input validation failed: the scan response did not match its schema, so the count is unknown",
                          validation, {})
        domain = (data.get("primaryDomain") or data.get("domain") or "unknown") if isinstance(data, dict) else "unknown"
        summary = {"domain": domain, "scanScope": SCAN_SCOPE,
                   "domainsScanned": to_int(data.get("domainsScanned")) if isinstance(data, dict) else None,
                   "totalDiscovered": to_int(data.get("totalDiscovered")) if isinstance(data, dict) else None,
                   "templatesScanned": to_int(data.get("templatesScanned")) if isinstance(data, dict) else None}
        problem = scan_problem(data)
        if problem:
            return failed(problem, validation, summary)
        findings = [f for f in data.get("findings") if is_live_match(f)
                    and finding_severity(f) in ("critical", "high")]
        risky = []
        risky_findings = []
        unscored = []
        no_cve = []
        for f in findings:
            percentile, score = finding_epss(f)
            if not finding_cves(f):
                no_cve.append(f)
            elif percentile is None:
                unscored.append(f)
            elif percentile >= EPSS_PERCENTILE_THRESHOLD:
                risky.append(describe(f, percentile, score))
                risky_findings.append(f)
        count = len(risky)
        summary["liveFindings"] = len(findings)
        summary["cveFindingsWithoutEpss"] = len(unscored)
        summary["findingsWithoutCve"] = len(no_cve)
        notes = (["No EPSS percentile on CVE finding: " + finding_name(f) + " at " + finding_where(f) for f in unscored[:20]]
                 + ["Not EPSS-scored (no CVE): " + finding_name(f) + " at " + finding_where(f) for f in no_cve[:20]])
        threshold = str(EPSS_PERCENTILE_THRESHOLD)
        if count == 0 and unscored:
            return failed(str(len(unscored)) + " live " + SCAN_SCOPE + "-severity CVE finding(s) for " + str(domain)
                          + " carry no usable EPSS percentile, so none can be shown to be below " + threshold,
                          validation, summary)
        capped = capped_note(data)
        if capped and count == 0:
            return failed(capped + "; zero high-EPSS findings on a partial scan is not a clean estate", validation, summary)
        result = {CRITERIA_KEY: count, "severityScope": SCAN_SCOPE, "epssPercentileThreshold": EPSS_PERCENTILE_THRESHOLD,
                  "hostsScanned": to_int(data.get("domainsScanned"))}
        if count > 0:
            result["evidenceItems"] = evidence_items(risky_findings)
        if count == 0:
            return create_response(
                result=result, validation=validation,
                pass_reasons=["No live " + SCAN_SCOPE + "-severity finding with EPSS percentile >= " + threshold
                              + " across " + str(summary["domainsScanned"]) + " host(s) of " + str(domain)],
                additional_findings=notes, input_summary=summary)
        fails = [str(count) + " live " + SCAN_SCOPE + "-severity finding(s) with EPSS percentile >= " + threshold
                 + " for " + str(domain)]
        if capped:
            fails.append(capped)
        return create_response(
            result=result, validation=validation, fail_reasons=fails,
            recommendations=["Remediate these first: EPSS rates them among the CVEs most likely to be exploited in the next 30 days"],
            additional_findings=risky[:50] + notes, input_summary=summary)
    except Exception as e:
        reason = "Transformation error, so the count is unknown: " + str(e)
        return create_response(result={CRITERIA_KEY: None},
                               validation={"status": "error", "errors": [], "warnings": []},
                               api_errors=[reason], transformation_errors=[str(e)], fail_reasons=[reason])
