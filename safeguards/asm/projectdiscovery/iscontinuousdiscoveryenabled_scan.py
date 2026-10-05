"""
Transformation: isContinuousDiscoveryEnabled (scan-backed)
Vendor: Project Discovery (subfinder + Nuclei, run by Spektrum)  |  Category: Attack Surface Management
Evaluates: Whether continuous external asset discovery runs for the passport domain.

Rule (approved by J.J., 1 Oct 2026): a connected ProjectDiscovery OS IS continuous discovery, because Spektrum
runs subfinder discovery of the passport domain on every nightly evaluation. So this criterion is true only when
THIS evaluation's discovery demonstrably completed: the scan succeeded, subfinder returned at least one host
beyond the seed domain, the response is intact and the scan is fresh.

Input: the runParallelASMScan response the noCriticalFindings workflow already fetches (subfinder discovery of the
passport domain, then nuclei critical-severity templates across up to 25 discovered hosts). No extra scan.
This is NOT the generic iscontinuousdiscoveryenabled.py, which reads scan-schedule fields this scan never emits.

Why "beyond the seed domain": IS seeds the host list with the passport domain before adding subfinder output, and
a subfinder call that errors or times out is swallowed into an empty list (IS src/models/integrations/asm/
nuclei.py _run_asm_async_in_thread). A failed discovery therefore looks like totalDiscovered == 1 with only the
seed in domainResults. The only positive evidence that discovery ran is a discovered host other than the seed.

Fails closed (False, reason in dataCollection.errors and transformation.errors), matching the sibling
knownExploitedVulnCount scan gate: a scan that did not complete (error envelope, rate-limited 429, timeout,
template-list fallback), scanned zero hosts or zero templates, reports a failed host or an error, carries no
findings list or a findings list shorter or longer than its own total (truncated), whose host counts disagree with
its own domainResults, that discovered no host beyond the seed, or that carries no timestamp within the last 48 h.
A capped scan (more hosts discovered than the 25 nuclei scanned) still passes: the cap trims the nuclei step, not
discovery, and totalDiscovered is the full subfinder count.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isContinuousDiscoveryEnabled"
MAX_SCAN_AGE_HOURS = 48


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
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def scan_problem(data):
    """None when the scan completed across at least one host with no failed host, no error and an intact
    findings list; else the reason. Same gate as knownexploitedvulncount.py."""
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
              if isinstance(r, dict) and r.get("status") != "success"]
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


def host_name(value):
    return str(value or "").strip().lower().rstrip(".")


def discovery_problem(data):
    """None when subfinder discovery of the passport domain demonstrably returned hosts; else the reason."""
    seed = host_name(data.get("primaryDomain"))
    if not seed:
        return "Scan carries no primaryDomain, so it is not a subfinder discovery of the passport domain"
    results = data.get("domainResults")
    if not isinstance(results, list) or not results:
        return "Scan of " + seed + " carries no per-host domainResults"
    hosts = [host_name(r.get("domain")) for r in results if isinstance(r, dict)]
    if len(hosts) != len(results) or "" in hosts:
        return "Scan of " + seed + " has malformed domainResults entries"
    scanned = to_int(data.get("domainsScanned"))
    discovered = to_int(data.get("totalDiscovered"))
    if discovered is None:
        return "Scan of " + seed + " carries no totalDiscovered count"
    if scanned != len(results):
        return ("Scan of " + seed + " is truncated or inconsistent: domainsScanned " + str(scanned)
                + " against " + str(len(results)) + " domainResults")
    capped = data.get("domainsCapped") is True
    if (capped and discovered <= scanned) or (not capped and discovered != scanned):
        return ("Scan of " + seed + " is truncated or inconsistent: totalDiscovered " + str(discovered)
                + " against " + str(scanned) + " scanned (domainsCapped " + str(capped) + ")")
    beyond_seed = [h for h in hosts if h != seed]
    if not beyond_seed or discovered < 2:
        return ("Subfinder discovered no host beyond the seed domain " + seed
                + " (discovery failed, timed out or found nothing)")
    return None


def scan_age_hours(data):
    """Hours since the scan's own timestamp, or None when it carries no parseable timestamp."""
    stamp = str(data.get("timestamp") or "").strip()
    if stamp.endswith("Z") or stamp.endswith("z"):
        stamp = stamp[:-1]
    try:
        scanned_at = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return None
    if scanned_at.tzinfo is not None:
        scanned_at = scanned_at.replace(tzinfo=None) - scanned_at.utcoffset()
    return (datetime.utcnow() - scanned_at).total_seconds() / 3600.0


def failed(reason, validation, summary):
    return create_response(result={CRITERIA_KEY: False}, validation=validation, api_errors=[reason],
                           transformation_errors=[reason], fail_reasons=[reason], input_summary=summary)


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={CRITERIA_KEY: False}, validation=validation,
                                   transformation_errors=["Input validation failed"],
                                   fail_reasons=["Input validation failed"])
        domain = (data.get("primaryDomain") or data.get("domain") or "unknown") if isinstance(data, dict) else "unknown"
        summary = {"domain": domain,
                   "domainsScanned": to_int(data.get("domainsScanned")) if isinstance(data, dict) else None,
                   "totalDiscovered": to_int(data.get("totalDiscovered")) if isinstance(data, dict) else None,
                   "templatesScanned": to_int(data.get("templatesScanned")) if isinstance(data, dict) else None}
        problem = scan_problem(data) or discovery_problem(data)
        if problem:
            return failed(problem, validation, summary)
        age = scan_age_hours(data)
        if age is None:
            return failed("Scan of " + str(domain) + " carries no parseable timestamp", validation, summary)
        if age < -1 or age > MAX_SCAN_AGE_HOURS:
            return failed("Scan of " + str(domain) + " is not from this evaluation: timestamp "
                          + str(data.get("timestamp")) + " is " + str(round(age, 1)) + " h old", validation, summary)
        seed = host_name(data.get("primaryDomain"))
        discovered = to_int(data.get("totalDiscovered"))
        scanned = to_int(data.get("domainsScanned"))
        capped = data.get("domainsCapped") is True
        result = {CRITERIA_KEY: True, "hostsDiscovered": discovered, "subdomainsDiscovered": discovered - 1,
                  "hostsScanned": scanned, "discoveryCapped": capped, "scannedAt": data.get("timestamp")}
        reasons = ["Subfinder discovery of " + seed + " completed in this evaluation: " + str(discovered - 1)
                   + " host(s) discovered beyond the seed domain, " + str(scanned) + " scanned by nuclei"]
        notes = []
        if capped:
            notes.append("Nuclei scanned " + str(scanned) + " of " + str(discovered)
                         + " discovered host(s); the cap limits vulnerability scanning, not discovery")
        return create_response(result=result, validation=validation, pass_reasons=reasons,
                               additional_findings=notes, input_summary=summary)
    except Exception as e:
        return create_response(result={CRITERIA_KEY: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
