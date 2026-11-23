"""
Transformation: isPatchManagementEnabled
Vendor: Qualys
Category: Security / Attack Surface Management

Evaluates whether patch management is enabled from a Qualys Host List VM
Detection reply. Any Fixed (patched) detection makes it enabled. No Fixed row
is a No only when the reply's request echo (echo_request=1) shows status
included Fixed; otherwise, and when no host was assessed, it is Not evaluated.

Expected response structure:
{
    "HOST_LIST_VM_DETECTION_OUTPUT": {
        "RESPONSE": {
            "DATETIME": "2026-03-19T16:53:03Z",
            "HOST_LIST": {              # absent when nothing matched: Not evaluated (no_data)
                "HOST": [               # single dict or list
                    {
                        "ID": "12345",
                        "IP": "10.0.0.1",
                        "DNS": "host.example.com",
                        "DETECTION_LIST": {
                            "DETECTION": [
                                {
                                    "QID": "1234",
                                    "STATUS": "Fixed",
                                    "IS_PATCHABLE": "1"
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }
}
"""

import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
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

    return data, {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"]
    }


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
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
                "schemaVersion": "1.0",
                "transformationId": "isPatchManagementEnabled",
                "vendor": "Qualys",
                "category": "Attack Surface Management"
            }
        }
    }


# --- Qualys detection reply: byte-identical in every transform that reads it (a test compares the copies) ---
OPEN_STATUSES = {'new', 'active', 'reopened'}


def detection_response(data):
    """HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE, or None when the body is not a detection reply."""
    output = data.get('HOST_LIST_VM_DETECTION_OUTPUT') if isinstance(data, dict) else None
    response = output.get('RESPONSE') if isinstance(output, dict) else None
    return response if isinstance(response, dict) else None


def status_token(value):
    """One status spelling: Qualys writes Re-Opened, REOPENED and Fixed, FIXED for the same state."""
    return str(value).strip().lower().replace('-', '').replace('_', '').replace(' ', '')


def echoed_statuses(data):
    """The detection statuses Qualys says it applied, or None when the reply carries no request echo.

    Qualys returns only New, Active and Re-Opened detections unless status= names others. With
    echo_request=1 it repeats the parameters it applied under HOST_LIST_VM_DETECTION_OUTPUT.REQUEST.
    That echo is the only proof of the filter: a definition can name Fixed and never send it
    (inputParameters on a GET without parametersIn "query" travel as an ignored body). An echo with
    no status parameter means Qualys applied its default.
    """
    output = data.get('HOST_LIST_VM_DETECTION_OUTPUT') if isinstance(data, dict) else None
    request = output.get('REQUEST') if isinstance(output, dict) else None
    param_list = request.get('PARAM_LIST') if isinstance(request, dict) else None
    params = param_list.get('PARAM') if isinstance(param_list, dict) else None
    if isinstance(params, dict):
        params = [params]
    if not isinstance(params, list):
        return None
    for param in params:
        if isinstance(param, dict) and str(param.get('KEY', '')).strip().lower() == 'status':
            return {status_token(v) for v in str(param.get('VALUE', '')).split(',') if v.strip()}
    return set(OPEN_STATUSES)


EMPTY = (None, '', [])  # xmltodict writes an empty element as None


def detection_hosts(response):
    """Host records in a detection RESPONSE; none when Qualys omits HOST_LIST, which means nothing assessed.

    A HOST_LIST that is present but empty, or holds anything but host records, raises: that is our read
    failing, not "nothing scanned", and grading the readable hosts would grade an unstated subset.
    """
    host_list = response.get('HOST_LIST')
    if host_list is None:
        return []
    hosts = host_list.get('HOST') if isinstance(host_list, dict) else None
    if isinstance(hosts, dict):
        hosts = [hosts]
    if not isinstance(hosts, list) or not hosts or any(not isinstance(host, dict) for host in hosts):
        raise ValueError("unreadable host list")
    return hosts


def detection_rows(host):
    """A host's detection records; none when DETECTION_LIST or DETECTION is empty.

    Any other shape, or any row that is not a record, raises: grading the readable rows would grade an
    unstated subset, so every reader treats an unreadable row the same way, as not measured.
    """
    if not isinstance(host, dict):
        raise ValueError("unreadable host record")
    detection_list = host.get('DETECTION_LIST')
    if detection_list in EMPTY:
        return []
    if not isinstance(detection_list, dict):
        raise ValueError("unreadable detection list")
    rows = detection_list.get('DETECTION')
    if rows in EMPTY:
        return []
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("unreadable detection row")
    return rows


def truncated(response):
    """True when Qualys stopped the host list at its record limit (WARNING code 1980)."""
    warning = response.get('WARNING')
    warnings = warning if isinstance(warning, list) else [warning]
    return any(isinstance(w, dict) and str(w.get('CODE', '')).strip() == '1980' for w in warnings)
# --- end Qualys detection reply ----------------------------------------------------------------------------


# The read is ours, so a gap in it is ours to fix: the customer is told so, and errorCode routes it to engineering.
NOT_OURS_TO_ASK = "Nothing is needed from you; this is on Spektrum's side."


def not_measured(criteria_key, reason, error_code, validation=None, transformation_errors=None, findings=None,
                 recommendations=(NOT_OURS_TO_ASK,)):
    """criteria_key None plus a coded dataCollection error, so the evaluator records Not evaluated."""
    response = create_response(
        result={criteria_key: None}, validation=validation,
        api_errors=[reason], fail_reasons=[reason], transformation_errors=transformation_errors,
        additional_findings=findings, recommendations=list(recommendations))
    response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response


# --- Qualys refusal: byte-identical in every Qualys transform (a test compares the copies) -------------------
VERIFY_ACCESS = "Verify the Qualys API credentials and the permissions of the Qualys user Spektrum connects as."
# Qualys's login and account refusals: 2000 Bad Login/Password, 2002 account inactive, 2003 registration incomplete.
QUALYS_LOGIN_CODES = {'2000', '2002', '2003'}


def vendor_refusal(data):
    """The reason when Qualys, or the relay in front of it, refused our credentials; None for any other reply.

    A refusal is the customer's to fix, so it is coded vendor_refusal with text the diagnosis reads as an auth
    failure. Every other error reply (a parameter Qualys rejected, a body we cannot read) stays ours.
    """
    if not isinstance(data, dict):
        return None
    simple = data.get('SIMPLE_RETURN')
    reply = simple.get('RESPONSE') if isinstance(simple, dict) else None
    if isinstance(reply, dict) and str(reply.get('CODE', '')).strip() in QUALYS_LOGIN_CODES:
        return ("Qualys refused the API login (authentication failed, Qualys code %s), so this check could not "
                "be evaluated." % str(reply.get('CODE')).strip())
    status = str(data.get('statusCode', data.get('status_code', ''))).strip()
    message = str(data.get('message', '')).upper()
    for code in ('401', '403'):
        if status == code or ('HTTP ' + code) in message:
            return "Qualys refused Spektrum's request (HTTP %s), so this check could not be evaluated." % code
    return None
# --- end Qualys refusal -----------------------------------------------------------------------------------------


NOT_SCANNED = "Confirm Qualys has scanned the hosts in scope."
NOT_READ = ("Spektrum's Qualys read does not yet include patched detections, so patch management "
            "could not be checked.")


def tally_statuses(hosts):
    """Detections per status across all hosts, in one pass; a row that is not a record raises."""
    tally = {}
    for host in hosts:
        for row in detection_rows(host):
            status = status_token(row.get("STATUS", "unknown"))[:32]
            tally[status] = tally.get(status, 0) + 1
    return tally


def transform(input):
    criteriaKey = "isPatchManagementEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        refusal = vendor_refusal(data)
        if refusal:
            return not_measured(criteriaKey, refusal, "vendor_refusal", validation=validation,
                                recommendations=(VERIFY_ACCESS,))

        if validation.get("status") == "failed":
            return not_measured(criteriaKey, "The Qualys response failed validation, so patch management could not be checked.",
                                "not_measured", validation=validation)

        response = detection_response(data)
        if response is None:
            # The workflow feeds this key getHostList, whose reply has no detection list, and an error envelope has
            # none either: nothing was measured, and the read is ours to fix.
            return not_measured(criteriaKey, NOT_READ, "not_measured", validation=validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        hosts = detection_hosts(response)
        response_datetime = response.get("DATETIME", "")
        host_count = len(hosts)
        statuses = tally_statuses(hosts)
        detection_count = statuses.get("fixed", 0)

        if host_count == 0:
            # No HOST_LIST is nothing assessed under ENG-1353, as in the asm/qualys siblings, not a measured No.
            return not_measured(criteriaKey, "Qualys returned no assessed hosts, so patch management could not be checked.",
                                "no_data", validation=validation,
                                recommendations=(NOT_SCANNED,))
        if detection_count == 0 and truncated(response):
            # One page with no Fixed row says nothing about the hosts Qualys cut off.
            return not_measured(criteriaKey, "Spektrum's Qualys read stopped at a page limit, so patch management "
                                "could not be checked.", "partial_read", validation=validation)
        if detection_count == 0 and 'fixed' not in (echoed_statuses(data) or set()):
            # No Fixed row is "nothing patched" only when the echo proves Fixed was asked for.
            return not_measured(criteriaKey, NOT_READ, "not_measured", validation=validation)

        is_enabled = detection_count > 0

        if is_enabled:
            pass_reasons.append(
                f"Patch management is enabled - {host_count} host(s) with {detection_count} patched (Fixed) detection(s) found"
            )
        else:
            fail_reasons.append(
                "No patched hosts found - no vulnerabilities with status Fixed were returned"
            )
            recommendations.append(
                "Verify that Qualys VM/VMDR is configured and that patches are being deployed to remediate detected vulnerabilities"
            )

        additional_findings = [{
            "metric": f"patchableDetections_{status_name}",
            "value": statuses[status_name],
            "reason": f"{statuses[status_name]} patchable detection(s) with status '{status_name}'"
        } for status_name in statuses]

        return create_response(
            result={
                criteriaKey: is_enabled,
                "hostCount": host_count,
                "patchedDetectionCount": detection_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "responseDateTime": response_datetime,
                "hostCount": host_count,
                "patchedDetectionCount": detection_count
            }
        )

    except Exception:
        return not_measured(criteriaKey, "The Qualys response could not be read, so patch management could not be checked.",
                            "not_measured", validation={"status": "error", "errors": [], "warnings": []},
                            transformation_errors=["unreadable value in the Qualys reply"])
