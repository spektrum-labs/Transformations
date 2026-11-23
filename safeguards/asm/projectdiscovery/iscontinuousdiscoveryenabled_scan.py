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

Fails closed, matching the sibling knownExploitedVulnCount scan gate, and never reports False for a scan that
measured nothing. None (Not evaluated), with the reason in dataCollection.errors and transformation.errors, for:
a scan that did not complete (error envelope, rate-limited 429, timeout, template-list fallback), scanned zero
hosts or zero templates, reports a failed host or an error (so an error on the discovery call), or carries no
findings list or one shorter or longer than its own total; one whose host counts disagree with its own
domainResults; a capped or time-limited partial that names no host beyond the seed; one with no timestamp, a
timestamp that cannot be read or one in the future (more than an hour ahead); a completed scan that discovered no
host beyond the seed (a swallowed subfinder error or timeout looks exactly like that, with no error recorded, so it
is not a proven negative); an input that failed validation; and an exception inside the transform.

False, graded, is reserved for a proven negative: a scan that completed with no error anywhere, so no error touches
the discovery evidence, whose counts agree and whose readable timestamp is older than 48 h (discovery has not run
in the window). It is False with the reason as a fail reason and nothing recorded as a data collection error.
Otherwise True.
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


# --- scan reason ----------------------------------------------------------------------------------------
# The Integration Service answers a scan it has no result for as {"status": "error", "reason": "<code>",
# "message": ...}: asm_scan_in_progress (a scan is still running), asm_scan_retry_backoff (the last scan
# produced nothing usable, so no new scan was started), asm_scan_shared_no_result and
# asm_scan_max_duration_exceeded. The code is passed on as dataCollection.errorCode, so a reader can tell a scan
# that is still running from a broken integration. An error reply measured nothing, so the criterion is None
# (Not evaluated), never False, whatever the reason: an asm_scan_ code, any other code, no reason, or a reason
# that is not a plain code (that one is dropped, and the text stays generic).
SCAN_REASON_MAX_LENGTH = 60
SCAN_REASON_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_"
SCAN_REASON_TEXT = {
    "asm_scan_in_progress": "the scan is still running; its result is read on the next evaluation",
    "asm_scan_retry_backoff": "the last scan produced no usable result, so a new scan has not started yet",
    "asm_scan_shared_no_result": "the scan that was already running produced no usable result",
    "asm_scan_max_duration_exceeded": "the scan ran past its time limit",
}


def scan_reason(data):
    """The reason code of a scan reply that is not a result: a plain lower-case code of at most 60 characters,
    else None (a successful scan, no reason, or a reason that is not a plain code)."""
    if not isinstance(data, dict) or data.get("status") == "success":
        return None
    reason = data.get("reason")
    if not isinstance(reason, str):
        return None
    reason = reason.strip().lower()
    if not reason or len(reason) > SCAN_REASON_MAX_LENGTH:
        return None
    for ch in reason:
        if ch not in SCAN_REASON_CHARS:
            return None
    return reason


def scan_status_problem(status, domain, reason):
    """The error text for a scan reply that is not a result."""
    if reason is None:
        return "Nuclei scan status: " + str(status) + " for " + str(domain)
    if reason.startswith("asm_scan_"):
        return ("Nuclei scan not evaluated (" + reason + "): "
                + SCAN_REASON_TEXT.get(reason, "the scan did not produce a result"))
    return "Nuclei scan status: " + str(status) + " (" + reason + ") for " + str(domain)


def with_error_code(response, error_code):
    """Label a reply with the reason code the Integration Service gave, when it gave one."""
    if error_code:
        response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response
# --- end scan reason -------------------------------------------------------------------------------------


def scan_problem(data):
    """None when the scan completed across at least one host with no failed host, no error and an intact
    findings list; else the reason. Same gate as knownexploitedvulncount.py."""
    if not isinstance(data, dict):
        return "No scan data"
    domain = data.get("primaryDomain") or data.get("domain") or "unknown"
    status = data.get("status", "unknown")
    if status != "success":
        return scan_status_problem(status, domain, scan_reason(data))
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


def is_true(value):
    return value is True or str(value).strip().lower() == "true"


def host_name(value):
    return str(value or "").strip().lower().rstrip(".")


def discovery_shape_problem(data):
    """None when the scan's own host counts and per-host results agree and name the passport domain; else the
    reason. A scan whose counts cannot be trusted measured nothing about discovery."""
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
    if (capped or is_true(data.get("scanTimeLimited"))) and not [h for h in hosts if h != seed]:
        return ("Scan of " + seed + " is partial (capped or stopped by its time limit) and names no host beyond the "
                "seed among the " + str(scanned) + " it covered, so discovery cannot be read from it")
    return None


def no_discovery_problem(data):
    """None when subfinder discovered at least one host beyond the seed domain; else the reason. Only called on
    a scan that passed scan_problem, discovery_shape_problem and timestamp_problem, so it completed with no error,
    its counts agree, it was not capped or time-limited and it is dated inside the window's past or present."""
    seed = host_name(data.get("primaryDomain"))
    hosts = [host_name(r.get("domain")) for r in data.get("domainResults")]
    discovered = to_int(data.get("totalDiscovered"))
    if not [h for h in hosts if h != seed] or discovered < 2:
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


def timestamp_problem(data):
    """None when the scan carries a readable timestamp that is not in the future; else the reason. A scan that
    cannot be placed in time cannot be placed in the evaluation window, so nothing is proven about it."""
    seed = host_name(data.get("primaryDomain"))
    age = scan_age_hours(data)
    if age is None:
        return "Scan of " + seed + " carries no parseable timestamp, so it cannot be placed in the evaluation window"
    if age < -1:
        return ("Scan of " + seed + " carries a timestamp in the future (" + str(data.get("timestamp"))
                + "), so it cannot be placed in the evaluation window")
    return None


def measured_false(reason, validation, summary):
    """A proven negative: the scan completed with no error and its counts agree, and its own date shows discovery
    has not run in the window. A graded False with the reason as a fail reason; nothing is recorded as a data collection error."""
    return create_response(result={CRITERIA_KEY: False}, validation=validation, fail_reasons=[reason],
                           input_summary=summary)


def not_evaluated(reason, validation, summary, error_code=None):
    """None (Not evaluated) with the reason in dataCollection.errors and transformation.errors."""
    return with_error_code(
        create_response(result={CRITERIA_KEY: None}, validation=validation, api_errors=[reason],
                        transformation_errors=[reason], fail_reasons=[reason], input_summary=summary),
        error_code)


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            reason = "Input validation failed: the scan response did not match its schema, so discovery is unknown"
            return create_response(result={CRITERIA_KEY: None}, validation=validation, api_errors=[reason],
                                   transformation_errors=[reason], fail_reasons=[reason])
        domain = (data.get("primaryDomain") or data.get("domain") or "unknown") if isinstance(data, dict) else "unknown"
        summary = {"domain": domain,
                   "domainsScanned": to_int(data.get("domainsScanned")) if isinstance(data, dict) else None,
                   "totalDiscovered": to_int(data.get("totalDiscovered")) if isinstance(data, dict) else None,
                   "templatesScanned": to_int(data.get("templatesScanned")) if isinstance(data, dict) else None}
        # Not evaluated (None, with the reason in dataCollection.errors): a scan that did not complete or reports
        # an error, one whose own counts disagree with its per-host results or that is partial with no host
        # beyond the seed, and one with no readable or a future timestamp.
        unmeasured = scan_problem(data) or discovery_shape_problem(data) or timestamp_problem(data)
        if unmeasured:
            return not_evaluated(unmeasured, validation, summary, scan_reason(data))
        # No host beyond the seed is Not evaluated: IS swallows a subfinder error or timeout into an empty list
        # with no error recorded, so this body cannot tell "found nothing" from "discovery failed".
        no_discovery = no_discovery_problem(data)
        if no_discovery:
            return not_evaluated(no_discovery, validation, summary)
        # Proven negative (a graded False, no error recorded): the scan completed with no error anywhere and is
        # older than the window (MAX_SCAN_AGE_HOURS), so discovery has not run in it.
        age = scan_age_hours(data)
        if age > MAX_SCAN_AGE_HOURS:
            return measured_false("Scan of " + str(domain) + " is not from this evaluation: timestamp "
                                  + str(data.get("timestamp")) + " is " + str(round(age, 1)) + " h old, beyond the "
                                  + str(MAX_SCAN_AGE_HOURS) + " h window", validation, summary)
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
        reason = "Transformation error, so discovery is unknown: " + str(e)
        return create_response(result={CRITERIA_KEY: None},
                               validation={"status": "error", "errors": [], "warnings": []},
                               api_errors=[reason], transformation_errors=[str(e)], fail_reasons=[reason])
