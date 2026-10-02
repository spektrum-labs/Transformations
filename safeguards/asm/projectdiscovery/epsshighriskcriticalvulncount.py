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
    if status != "success":
        return "Nuclei scan status: " + str(status) + " for " + str(domain)
    scanned = to_int(data.get("domainsScanned"))
    if scanned is None or scanned <= 0:
        return "Nuclei scanned zero hosts for " + str(domain)
    templates = to_int(data.get("templatesScanned"))
    if templates is None or templates <= 0:
        return "Nuclei ran zero templates for " + str(domain)
    failed = [r.get("domain", "unknown") for r in (data.get("domainResults") or [])
              if isinstance(r, dict) and r.get("status") not in ("success", "unresponsive")]
    errors = data.get("errors") or []
    if failed or errors:
        return "Nuclei scan failed for " + str(max(len(failed), len(errors))) + " host(s) of " + str(domain)
    findings = data.get("findings")
    if not isinstance(findings, list):
        return "Nuclei scan for " + str(domain) + " carries no findings list"
    total = to_int(data.get("total"))
    if total is None or total != len(findings):
        return ("Nuclei findings list for " + str(domain) + " is truncated or inconsistent: " + str(len(findings))
                + " finding(s) against a total of " + str(data.get("total")))
    return None


def capped_note(data):
    """The reason a zero would be partial (more hosts discovered than scanned), else None."""
    if data.get("domainsCapped") is not True:
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


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={CRITERIA_KEY: None}, validation=validation,
                                   transformation_errors=["Input validation failed"],
                                   fail_reasons=["Input validation failed"])
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
        return create_response(result={CRITERIA_KEY: None},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
