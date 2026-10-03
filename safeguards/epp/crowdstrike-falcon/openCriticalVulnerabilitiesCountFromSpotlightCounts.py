"""Transformation: openCriticalVulnerabilitiesCount (CrowdStrike Falcon Spotlight, from the vendor's own counts).

Vendor: CrowdStrike  |  Category: Endpoint Security
Integrations: Crowdstrike - XDR Falcon (765f3eb2) and CrowdStrike Falcon-Endpoint Security (d61a39d7), through the
definition workflow spotlightCriticalHighCounts.

openCriticalVulnerabilitiesCount: open or reopened Spotlight instances with CRITICAL severity.

WHY COUNTS AND NOT RECORDS. The *FromSpotlight.py files read every open critical/high record from
GET /spotlight/combined/vulnerabilities/v1 (page size 5000, at most 20 pages = 100,000 records) and count them. Large
estates hold more than that (on 2-3 Oct 2026 one estate held about 1M open/reopened critical+high instances and another
about 100k), so every read stopped at the page cap and those checks were Unevaluated ("a partial read is not scored").
Reading a million records with facet=cve on every evaluation is not workable. CrowdStrike already answers the exact
question: GET /spotlight/queries/vulnerabilities/v1?filter=<FQL>&limit=1 returns meta.pagination.total, the number of
vulnerability instances (one CVE on one host, the same record id the combined endpoint returns) that match the filter,
over the whole estate. That is a complete read of the count, computed by the vendor; nothing is sampled or capped.

Input: the spotlightCriticalHighCounts workflow output, one block per step (IS merge + output.key):
  openCriticalHigh  filter status:['open','reopen']+cve.severity:['CRITICAL','HIGH']
  openCritical      filter status:['open','reopen']+cve.severity:'CRITICAL'
  openHigh          filter status:['open','reopen']+cve.severity:'HIGH'
  overdueCritical   filter status:['open','reopen']+cve.severity:'CRITICAL'+created_timestamp:<'{$utcNow-15d}'
  overdueHigh       filter status:['open','reopen']+cve.severity:'HIGH'+created_timestamp:<'{$utcNow-30d}'
Each block is the vendor body {"meta": {"pagination": {"limit": 1, "total": N, ...}}, "resources": [<id>], "errors": []}
(IS's {$utcNow-Nd} is the call time minus N days, RFC 3339 UTC). created_timestamp is when Spotlight first detected
the instance, the same field the record-reading files age.

Numbers emitted (every file emits the same set, its own key first):
  openCriticalVulnerabilitiesCount         openCritical total
  openHighSeverityVulnerabilitiesCount     openHigh total
  overdueCriticalHighVulnerabilitiesCount  overdueCritical total + overdueHigh total (CISA BOD 19-02 windows: critical
                                           more than 15 days, high more than 30 days since first detection)
  isPatchManagementValid (its own file only) overdueCriticalHighVulnerabilitiesCount == 0
  overdueCriticalCount, overdueHighCount, spotlightOpenCriticalHighTotal  evidence

Fail closed: anything that is not five complete, consistent vendor counts returns every key as None with
dataCollection "error" (Unevaluated): no envelope, an IS or vendor error, a missing block (a workflow step that did not
run), a block without a numeric meta.pagination.total, a resources list that contradicts its total (ids when the total
is 0, none when it is above 0, more ids than the total, a non-string id), or counts that disagree with each other:
openCritical + openHigh must equal openCriticalHigh (catches a severity filter the vendor ignored), and each overdue
count must not exceed its open count (catches a date filter that widened the set).

Missing scope (SCOPE-NOT-GRANTED): CrowdStrike answers a client without "Vulnerabilities: Read" with HTTP 403
{"errors": [{"code": 403, "message": "access denied, scope not permitted"}]}. When the method opts in to
Integration-Service's vendorErrorAsResponse for that 403, IS hands it over in the block as
{"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <the vendor body>}}. That refusal says nothing
about the estate: every key stays None and dataCollection carries errorCode "scope_not_granted" and requiredScope
"Vulnerabilities: Read". Any other handed-over refusal is Unevaluated with errorCode "vendor_refusal".

Measured zero: a block whose meta.pagination.total is explicitly 0 (an int, or the digit string "0" as stored evidence
renders it) with an empty resources list and no errors is the vendor's own count and reads 0. A missing, null or
non-numeric total stays Unevaluated.
"""
import json
from datetime import datetime

KEY = "openCriticalVulnerabilitiesCount"
KEY_CRITICAL = "openCriticalVulnerabilitiesCount"
KEY_HIGH = "openHighSeverityVulnerabilitiesCount"
KEY_OVERDUE = "overdueCriticalHighVulnerabilitiesCount"
KEY_VALID = "isPatchManagementValid"
IS_BOOLEAN = False
BLOCKS = ["openCriticalHigh", "openCritical", "openHigh", "overdueCritical", "overdueHigh"]
RECOMMENDATION = ("Patch or mitigate the open critical vulnerabilities in Falcon Spotlight, starting with those first detected more than 15 days ago.")


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
        return unwrap(input_data["data"]), input_data["validation"]
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    return unwrap(input_data), validation


def unwrap(data):
    """Peel IS/TS wrapper objects (apiResponse, response, result, Output) until a body is left."""
    wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
    for i in range(3):
        if not isinstance(data, dict):
            return data
        # Never peel past a wrapper that reports an error: the caller must see it and fail closed.
        if data.get("error") or data.get("errors"):
            return data
        unwrapped = False
        for key in wrapper_keys:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
                unwrapped = True
                break
        if not unwrapped:
            break
    return data


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
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
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "CrowdStrike", "category": "Endpoint Security"},
        },
    }


def unevaluated_result():
    result = {KEY: None}
    for k in [KEY_CRITICAL, KEY_HIGH, KEY_OVERDUE]:
        result[k] = None
    return result


SCOPE_NOT_GRANTED = "scope_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_SCOPE = "Vulnerabilities: Read"
SCOPE_PROBLEM = ("SCOPE-NOT-GRANTED: CrowdStrike answered HTTP 403 \"access denied, scope not permitted\" on "
                 "GET /spotlight/queries/vulnerabilities/v1, so the Falcon API client does not hold "
                 "Vulnerabilities: Read (Falcon Spotlight). Nothing was measured; this is not a posture result.")
SCOPE_RECOMMENDATION = ("In the Falcon console (Support and Resources > API Clients and Keys), edit the existing "
                        "Spektrum API client and add Vulnerabilities: Read; the Client ID and Client Secret do not "
                        "change. If Falcon Spotlight is not licensed, tell your Spektrum contact so this check can be "
                        "taken off your requirements.")
DEFAULT_RECOMMENDATION = ("Confirm the Falcon API client has Vulnerabilities: Read and that Falcon Spotlight is "
                          "licensed and assessing hosts.")


def unevaluated(problem, validation, error_code=None):
    recommendation = SCOPE_RECOMMENDATION if error_code == SCOPE_NOT_GRANTED else DEFAULT_RECOMMENDATION
    out = create_response(unevaluated_result(), validation, fail_reasons=[problem], api_errors=[problem],
                          recommendations=[recommendation])
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


def refusal(block):
    """(errorCode, problem) when a block is a CrowdStrike refusal rather than a count, else None."""
    if not isinstance(block, dict):
        return None
    if "vendorErrorAsResponse" in block:
        marker = block.get("vendorErrorAsResponse")
        status = marker.get("status") if isinstance(marker, dict) else None
        body = decoded(marker.get("body")) if isinstance(marker, dict) else None
        errors = body.get("errors") if isinstance(body, dict) else None
        if status == 403 and scope_refused(errors):
            return SCOPE_NOT_GRANTED, SCOPE_PROBLEM
        return VENDOR_REFUSAL, ("CrowdStrike refused a Spotlight count (handed over by Integration-Service, HTTP "
                                + str(status)[:10] + "); nothing was measured.")
    if scope_refused(block.get("errors")):
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


def block_total(name, block):
    """(total, None) for one complete vendor count, or (None, problem)."""
    block = unwrap(block)
    if not isinstance(block, dict):
        return None, "The " + name + " Spotlight count is missing; the workflow did not deliver every count."
    errors = block.get("errors")
    if errors:
        return None, "CrowdStrike Spotlight returned errors for the " + name + " count: " + json.dumps(errors)[:300]
    if block.get("error"):
        return None, ("The " + name + " Spotlight count failed: "
                      + str(block.get("message") or block.get("errorMessage") or "error")[:300])
    meta = block.get("meta")
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    resources = block.get("resources")
    if not isinstance(pagination, dict) or not isinstance(resources, list):
        return None, "The " + name + " block is not a Spotlight query envelope (resources list and meta.pagination)."
    total = as_count(pagination.get("total"))
    if total is None:
        return None, "The " + name + " count has no numeric meta.pagination.total; nothing was measured."
    for rid in resources:
        if not isinstance(rid, str) or not rid:
            return None, "The " + name + " count lists an id that is not a string; the response is not clean."
    if total == 0 and len(resources) > 0:
        return None, "The " + name + " count says 0 but lists ids; the response contradicts itself."
    if total > 0 and len(resources) == 0:
        return None, "The " + name + " count says " + str(total) + " but lists no ids; the response contradicts itself."
    if len(resources) > total:
        return None, "The " + name + " count lists more ids than its total; the response contradicts itself."
    return total, None


def measure(data):
    """Return (numbers, None) for five complete, consistent counts, or (None, problem)."""
    if not isinstance(data, dict):
        return None, "No CrowdStrike Spotlight count envelope; nothing to evaluate."
    if data.get("error"):
        return None, "The Spotlight counts failed: " + str(data.get("message") or data.get("errorMessage") or "error")[:300]
    if data.get("errors"):
        return None, "CrowdStrike Spotlight returned errors: " + json.dumps(data.get("errors"))[:300]
    totals = {}
    for name in BLOCKS:
        if name not in data:
            return None, ("The " + name + " Spotlight count is missing; the workflow did not deliver every count, so "
                          "nothing is scored.")
        total, problem = block_total(name, data.get(name))
        if problem:
            return None, problem
        totals[name] = total
    if totals["openCritical"] + totals["openHigh"] != totals["openCriticalHigh"]:
        return None, ("Spotlight counts disagree: " + str(totals["openCritical"]) + " critical + "
                      + str(totals["openHigh"]) + " high is not the " + str(totals["openCriticalHigh"])
                      + " open critical+high total; not scored.")
    if totals["overdueCritical"] > totals["openCritical"] or totals["overdueHigh"] > totals["openHigh"]:
        return None, "Spotlight counts disagree: an overdue count exceeds its open count; not scored."
    numbers = {
        KEY_CRITICAL: totals["openCritical"],
        KEY_HIGH: totals["openHigh"],
        KEY_OVERDUE: totals["overdueCritical"] + totals["overdueHigh"],
        "overdueCriticalCount": totals["overdueCritical"],
        "overdueHighCount": totals["overdueHigh"],
        "spotlightOpenCriticalHighTotal": totals["openCriticalHigh"],
    }
    numbers[KEY_VALID] = numbers[KEY_OVERDUE] == 0
    return numbers, None


def first_refusal(data):
    if not isinstance(data, dict):
        return None
    found = refusal(data)
    if found:
        return found
    for name in BLOCKS:
        found = refusal(unwrap(data.get(name)))
        if found:
            return found
    return None


def transform(input):
    try:
        data, validation = extract_input(input)
        refused = first_refusal(data)
        if refused:
            return unevaluated(refused[1], validation, refused[0])
        numbers, problem = measure(data)
        if problem:
            return unevaluated(problem, validation)
        result = {KEY: numbers[KEY]}
        for k in [KEY_CRITICAL, KEY_HIGH, KEY_OVERDUE, "overdueCriticalCount", "overdueHighCount",
                  "spotlightOpenCriticalHighTotal"]:
            if k != KEY:
                result[k] = numbers[k]
        summary = ("Spotlight vendor counts over the whole estate (" + str(numbers["spotlightOpenCriticalHighTotal"])
                   + " open/reopened critical+high instances): " + str(numbers[KEY_CRITICAL]) + " critical, "
                   + str(numbers[KEY_HIGH]) + " high, " + str(numbers[KEY_OVERDUE])
                   + " past the BOD 19-02 window (" + str(numbers["overdueCriticalCount"]) + " critical > 15 days, "
                   + str(numbers["overdueHighCount"]) + " high > 30 days).")
        passes = []
        fails = []
        recs = []
        if IS_BOOLEAN:
            good = numbers[KEY] is True
        else:
            good = numbers[KEY] == 0
        if good:
            passes.append(summary)
        else:
            fails.append(summary)
            recs.append(RECOMMENDATION)
        return create_response(result, validation, pass_reasons=passes, fail_reasons=fails, recommendations=recs,
                               input_summary=numbers)
    except Exception as e:
        return create_response(unevaluated_result(), {"status": "error", "errors": [], "warnings": []},
                               fail_reasons=["Transformation error: " + str(e)[:300]],
                               transformation_errors=[str(e)[:300]])
