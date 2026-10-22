"""Transformation: isFreeOfPHP2ShellFindings (CrowdStrike Falcon Spotlight, getSpotlightPHP2ShellVulnerabilities).

Vendor: CrowdStrike  |  Category: Endpoint Security
Advisory: PHP2Shell (ADV-2026-10-PHP2SHELL). Two flaws in PHP core, CVE-2026-109618 and CVE-2026-109619 (CVSS 9.2),
fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35, published 21 Oct 2026. The check reads the customer's own
vulnerability scanner findings for either CVE.

Input: getSpotlightPHP2ShellVulnerabilities, GET /spotlight/combined/vulnerabilities/v1 with the FQL filter
cve.id:['CVE-2026-109618','CVE-2026-109619'] and facet=cve and facet=host_info, with NO status filter, so open,
reopened, closed and expired records all come back. IS pages it on meta.pagination.after (cursor, page size 5000,
at most 20 pages, the same paging as getSpotlightVulnerabilitiesCombined), merges the pages into `resources` and
keeps meta.pagination with the vendor's `total` (`truncated` when maxPages stopped it; the envelope may also
carry `paginationTruncated`). One record is one
vulnerability on one asset.

Vendor reference (CrowdStrike's published API reference, developer.crowdstrike.com, Spotlight Vulnerabilities
collection, and CrowdStrike's falcon-mcp FQL guide for that endpoint): cve.id, status, host_info.internet_exposure,
closed_timestamp and updated_timestamp are documented filter fields; facets are host_info, remediation, cve and
evaluation_logic; limit max 5000 with an `after` cursor. status values: open, closed, reopen, expired.
host_info.internet_exposure values: Yes, No, Pending. host_info.managed_by values: "Falcon sensor", Unmanaged
(an Unmanaged asset is one Spotlight knows from another data provider, not from a sensor on the host).
UNVERIFIED: that the host_info facet returns internet_exposure and managed_by on each record under those names
(they are documented as filter fields; no stored Spotlight evidence with this facet was available to read).
Without them a finding still reads Exposed (risk "unknown") and a clean read stays Not evaluated, never True.

Criterion (True = clean, False = exposed, None = not evaluated):
  False (Exposed)      any record for either CVE whose status is open or reopen, suppressed or not. A finding
                       counts even when the rest of the read is incomplete: evidence found is evidence.
  True (Not exposed)   only from a whole, recent, credentialed read with zero open findings:
                         - whole: meta.pagination.total is a count, `resources` holds exactly that many records,
                           not truncated, no repeated id, every record has id, status, cve.id and a readable
                           updated_timestamp, and every record is for one of the two CVEs (the filter was applied);
                         - the detection content is current: at least one record for either CVE exists. Spotlight
                           has no field that says which CVEs its content covers, so an empty answer cannot tell
                           "no PHP2Shell here" from "the PHP2Shell detections have not reached this tenant yet";
                         - recent: every record was updated on or after 21 Oct 2026, and no record is expired
                           (an expired record is an asset Spotlight stopped seeing, so its state is unknown);
                         - credentialed: every record is on an asset with the Falcon sensor (on-host assessment
                           reads installed package versions, so it sees distro backports). A record from an
                           Unmanaged asset, or one with no managed_by, leaves the clean answer Not evaluated.
                       Known limit: Spotlight assesses hosts it knows. A web server with no Falcon sensor and no
                       other data provider is not in this read at all; this read cannot show that every web host
                       is covered, so True means "every PHP2Shell record Spotlight holds for this tenant is closed".
  None (Not evaluated) everything else: a refusal (missing Vulnerabilities: Read scope, or any other handed-over
                       vendor error), an error body, no envelope, a partial, capped or inconsistent read, an empty
                       read, a stale or expired record, or an Unmanaged asset, with no open finding.

Supporting fields:
  php2shellRiskLevel   high (an open finding on an asset Spotlight marks internet-facing, internet_exposure Yes) |
                       standard (every open finding is on an asset marked internet_exposure No) |
                       unknown (exposed but internet exposure Pending or missing; also on Not evaluated) | none
  php2shellVerdict     Exposed | Not exposed | Not evaluated
  php2shellOpenFindings, php2shellAffectedAssets, php2shellInternetFacingAssets, php2shellOpenCves,
  php2shellRecordsRead, php2shellRecordsTotal (not criteria: working figures for the evidence)
"""
import json
from datetime import datetime

KEY = "isFreeOfPHP2ShellFindings"
RISK_FIELD = "php2shellRiskLevel"
VERDICT_FIELD = "php2shellVerdict"
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
PUBLISHED = datetime(2026, 10, 21, 0, 0, 0)
OPEN_STATUSES = ["open", "reopen"]
KNOWN_STATUSES = ["open", "reopen", "closed", "expired"]
SENSOR_MANAGED = "falcon sensor"
MAX_LISTED_ASSETS = 20

SCOPE_NOT_GRANTED = "scope_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_SCOPE = "Vulnerabilities: Read"
SCOPE_PROBLEM = ("SCOPE-NOT-GRANTED: CrowdStrike answered HTTP 403 \"access denied, scope not permitted\" on "
                 "GET /spotlight/combined/vulnerabilities/v1, so the Falcon API client does not hold "
                 "Vulnerabilities: Read (Falcon Spotlight). Nothing was measured; PHP2Shell exposure is not evaluated.")
SCOPE_RECOMMENDATION = ("In the Falcon console (Support and Resources > API Clients and Keys), edit the existing "
                        "Spektrum API client and add Vulnerabilities: Read; the Client ID and Client Secret do not "
                        "change. If Falcon Spotlight is not licensed, PHP2Shell exposure cannot be read from Falcon.")
DEFAULT_RECOMMENDATION = ("Confirm the Falcon API client has Vulnerabilities: Read and that Falcon Spotlight is "
                          "licensed and assessing your web servers.")
EXPOSED_RECOMMENDATION = ("Update PHP on every listed asset to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your "
                          "distribution's patched package) and restart every PHP worker (PHP-FPM pools, Apache, "
                          "LiteSpeed). Start with internet-facing assets; take any you cannot patch today off the "
                          "internet.")


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, bytes):
        try:
            input_data = input_data.decode("utf-8")
        except Exception:
            input_data = ""
    if isinstance(input_data, str):
        try:
            input_data = json.loads(input_data)
        except Exception:
            input_data = {}
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_err_list or transform_err_list) else "success",
                               "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success", "errors": transform_err_list,
                               "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "CrowdStrike", "category": "Endpoint Security"},
        },
    }


def empty_counts():
    return {"php2shellOpenFindings": None, "php2shellAffectedAssets": None, "php2shellInternetFacingAssets": None,
            "php2shellOpenCves": [], "php2shellRecordsRead": None, "php2shellRecordsTotal": None}


def unevaluated(problem, validation, error_code=None, counts=None):
    recommendation = SCOPE_RECOMMENDATION if error_code == SCOPE_NOT_GRANTED else DEFAULT_RECOMMENDATION
    result = {KEY: None, RISK_FIELD: "unknown", VERDICT_FIELD: "Not evaluated"}
    result.update(counts or empty_counts())
    out = create_response(result, validation, fail_reasons=[problem], api_errors=[problem],
                          recommendations=[recommendation], input_summary=counts or {})
    if error_code:
        collection = out["additionalInfo"]["dataCollection"]
        collection["errorCode"] = error_code
        if error_code == SCOPE_NOT_GRANTED:
            collection["requiredScope"] = REQUIRED_SCOPE
    return out


def decoded(body):
    """A vendor body as an object: dicts as they are, JSON text or bytes parsed, anything else None."""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except Exception:
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return None
    return body


def scope_refused(errors):
    """True only for CrowdStrike's missing-scope answer: an error with code 403 and "scope not permitted"."""
    if not isinstance(errors, list):
        return False
    for err in errors:
        if not isinstance(err, dict):
            continue
        message = err.get("message")
        if str(err.get("code")) == "403" and isinstance(message, str) and "scope not permitted" in message.lower():
            return True
    return False


def refusal(data):
    """(errorCode, problem) when the body is a CrowdStrike refusal rather than Spotlight data, else None."""
    if not isinstance(data, dict):
        return None
    if "vendorErrorAsResponse" in data:
        marker = data.get("vendorErrorAsResponse")
        status = marker.get("status") if isinstance(marker, dict) else None
        body = decoded(marker.get("body")) if isinstance(marker, dict) else None
        errors = body.get("errors") if isinstance(body, dict) else None
        if status == 403 and scope_refused(errors):
            return SCOPE_NOT_GRANTED, SCOPE_PROBLEM
        return VENDOR_REFUSAL, ("CrowdStrike refused the Spotlight call (handed over by Integration-Service, HTTP "
                                + str(status)[:10] + "); PHP2Shell exposure is not evaluated.")
    if scope_refused(data.get("errors")):
        return SCOPE_NOT_GRANTED, SCOPE_PROBLEM
    return None


def as_count(value):
    """A non-negative int from an int or a digit string (stored evidence stringifies numbers), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_true(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def parse_stamp(value):
    """ISO-8601 UTC ('2026-10-22T12:00:00Z', optional fraction) -> naive UTC datetime, or None."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    try:
        return datetime.fromisoformat(value[:19])
    except Exception:
        return None


def text(value):
    return value.strip() if isinstance(value, str) else ""


def record_cve(rec):
    cve = rec.get("cve")
    cve_id = cve.get("id") if isinstance(cve, dict) else None
    if not text(cve_id):
        cve_id = rec.get("vulnerability_id")
    return text(cve_id).upper()


def host_field(rec, name):
    host = rec.get("host_info")
    return text(host.get(name)) if isinstance(host, dict) else ""


def asset_label(rec):
    name = host_field(rec, "hostname")
    if name:
        return name[:80]
    return "asset " + text(rec.get("aid"))[:12]


def open_findings(resources):
    """Every well-formed open or reopened record for either CVE, wherever it sits in the read."""
    found = []
    seen = {}
    if not isinstance(resources, list):
        return found
    for rec in resources:
        if not isinstance(rec, dict):
            continue
        if record_cve(rec) not in CVES:
            continue
        if text(rec.get("status")).lower() not in OPEN_STATUSES:
            continue
        rid = text(rec.get("id"))
        if rid and rid in seen:
            continue
        if rid:
            seen[rid] = True
        found.append(rec)
    return found


def risk_of(findings):
    exposures = [host_field(rec, "internet_exposure").lower() for rec in findings]
    if "yes" in exposures:
        return "high"
    if exposures and all(e == "no" for e in exposures):
        return "standard"
    return "unknown"


def exposure_counts(findings, resources, total):
    assets = {}
    facing = {}
    cves = {}
    for rec in findings:
        label = asset_label(rec)
        assets[text(rec.get("aid")) or label] = label
        if host_field(rec, "internet_exposure").lower() == "yes":
            facing[text(rec.get("aid")) or label] = label
        cves[record_cve(rec)] = True
    return {
        "php2shellOpenFindings": len(findings),
        "php2shellAffectedAssets": len(assets),
        "php2shellInternetFacingAssets": len(facing),
        "php2shellOpenCves": sorted(cves.keys()),
        "php2shellRecordsRead": len(resources) if isinstance(resources, list) else 0,
        "php2shellRecordsTotal": total,
    }, sorted(assets.values())


def read_problem(data, resources, total):
    """Why the read is not whole, or None when it is."""
    meta = data.get("meta")
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    if not isinstance(resources, list) or not isinstance(pagination, dict):
        return "The response is not a Spotlight vulnerabilities envelope (resources list and meta.pagination)."
    if total is None:
        return "Spotlight meta.pagination.total is missing or not a count, so a complete read cannot be shown."
    if is_true(pagination.get("truncated")) or is_true(meta.get("truncated")) or is_true(data.get("truncated")) \
            or is_true(data.get("paginationTruncated")):
        return ("Read stopped at the page limit (" + str(len(resources)) + " of " + str(total)
                + " records); a partial read is not scored.")
    if len(resources) != total:
        return "Read " + str(len(resources)) + " of " + str(total) + " Spotlight records; a partial read is not scored."
    return None


def clean_problem(resources):
    """Why a whole read with no open finding still cannot read as clean, or None."""
    if not resources:
        return ("Spotlight returned no record for CVE-2026-109618 or CVE-2026-109619. Spotlight does not say which "
                "CVEs its detection content covers, so an empty answer cannot tell 'no PHP2Shell here' from 'the "
                "PHP2Shell detections have not reached this tenant yet'; exposure is not evaluated.")
    seen = {}
    for rec in resources:
        if not isinstance(rec, dict):
            return "A Spotlight record is not an object."
        rid = rec.get("id")
        status = text(rec.get("status")).lower()
        updated = parse_stamp(rec.get("updated_timestamp"))
        if not isinstance(rid, str) or not rid or not status or updated is None:
            return "A Spotlight record has no id, status or readable updated_timestamp."
        if rid in seen:
            return "Spotlight record " + rid[:40] + " appears twice in the merged pages; the read is not clean."
        seen[rid] = True
        if record_cve(rec) not in CVES:
            return ("A Spotlight record is for " + record_cve(rec)[:40] + ", not a PHP2Shell CVE, so the CVE filter "
                    "was not applied; the read is not scored.")
        if status not in KNOWN_STATUSES:
            return "A Spotlight record has an unrecognised status (" + status[:20] + "); the read is not scored."
        if status == "expired":
            return ("A PHP2Shell record is expired: Spotlight stopped seeing that asset, so its current state is "
                    "unknown; exposure is not evaluated.")
        if updated < PUBLISHED:
            return ("A PHP2Shell record was last updated before 21 Oct 2026, so it predates the fixed releases and "
                    "cannot show the asset's state now; exposure is not evaluated.")
        if host_field(rec, "managed_by").lower() != SENSOR_MANAGED:
            return ("A PHP2Shell record is on an asset without the Falcon sensor (managed_by "
                    + (host_field(rec, "managed_by")[:30] or "missing")
                    + "). Only on-host assessment reads installed package versions, so a closed record there "
                    "cannot show the asset is patched; exposure is not evaluated.")
    return None


def transform(input):
    try:
        data, validation = extract_input(input)
        refused = refusal(data)
        if refused:
            return unevaluated(refused[1], validation, refused[0])
        if not isinstance(data, dict):
            return unevaluated("No CrowdStrike Spotlight response envelope; PHP2Shell exposure is not evaluated.",
                               validation)
        resources = data.get("resources")
        meta = data.get("meta")
        pagination = meta.get("pagination") if isinstance(meta, dict) else None
        total = as_count(pagination.get("total")) if isinstance(pagination, dict) else None
        findings = open_findings(resources)
        if findings:
            counts, assets = exposure_counts(findings, resources, total)
            risk = risk_of(findings)
            result = {KEY: False, RISK_FIELD: risk, VERDICT_FIELD: "Exposed"}
            result.update(counts)
            reasons = ["Falcon Spotlight has " + str(counts["php2shellOpenFindings"]) + " open PHP2Shell finding(s) ("
                       + ", ".join(counts["php2shellOpenCves"]) + ") on " + str(counts["php2shellAffectedAssets"])
                       + " asset(s), " + str(counts["php2shellInternetFacingAssets"])
                       + " of them marked internet-facing."]
            if risk == "unknown":
                reasons.append("Spotlight does not say whether every affected asset is internet-facing; risk level "
                               "unknown.")
            whole = read_problem(data, resources, total) if not data.get("errors") else "The body carries errors."
            if whole:
                reasons.append("The read was not whole (" + whole + "); there may be more findings.")
            listed = assets[:MAX_LISTED_ASSETS]
            findings_out = ["Affected asset: " + a for a in listed]
            if len(assets) > MAX_LISTED_ASSETS:
                findings_out.append("... and " + str(len(assets) - MAX_LISTED_ASSETS) + " more")
            return create_response(result, validation, fail_reasons=reasons, recommendations=[EXPOSED_RECOMMENDATION],
                                   input_summary=counts, findings=findings_out)
        errors = data.get("errors")
        if errors:
            return unevaluated("CrowdStrike Spotlight returned errors: " + json.dumps(errors)[:300], validation)
        if data.get("error"):
            return unevaluated("The Spotlight call failed: "
                               + str(data.get("message") or data.get("errorMessage") or "error")[:300], validation)
        problem = read_problem(data, resources, total)
        if problem:
            return unevaluated(problem, validation)
        counts, assets = exposure_counts([], resources, total)
        problem = clean_problem(resources)
        if problem:
            return unevaluated(problem, validation, counts=counts)
        result = {KEY: True, RISK_FIELD: "none", VERDICT_FIELD: "Not exposed"}
        result.update(counts)
        reason = ("Spotlight read whole (" + str(total) + " PHP2Shell record(s)): every one is closed, on a "
                  "Falcon-sensor asset, and updated since 21 Oct 2026. No open finding for CVE-2026-109618 or "
                  "CVE-2026-109619. Hosts without a Falcon sensor are not part of this read.")
        return create_response(result, validation, pass_reasons=[reason], input_summary=counts)
    except Exception as e:
        out = unevaluated("Transformation error: " + str(e)[:300], {"status": "error", "errors": [], "warnings": []})
        out["additionalInfo"]["transformation"]["status"] = "error"
        out["additionalInfo"]["transformation"]["errors"] = [str(e)[:300]]
        return out
