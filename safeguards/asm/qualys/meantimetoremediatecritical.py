"""
Transformation: meanTimeToRemediateCritical
Vendor: Qualys  |  Category: Attack Surface Management
Evaluates: Average days to remediate critical vulnerabilities.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "meanTimeToRemediateCritical", "vendor": "Qualys", "category": "Attack Surface Management"}
        }
    }


TRUNCATION_WARNING_CODE = '1980'


def detection_status(detection):
    """The detection state, folded to one token.

    Qualys ships one state in two casings and two separator conventions. Host List Detection's
    own description names them NEW, ACTIVE, FIXED, REOPENED (VM/PC API user guide p1119) while
    the status= parameter table on p1132 names them New, Active, Re-Opened, Fixed, and the
    published output samples in that section carry Active 43 times and ACTIVE 5 times. An exact
    membership test drops whichever casing the platform happens to emit, so fold before
    comparing.
    """
    value = detection.get('STATUS') if isinstance(detection, dict) else None
    if not isinstance(value, str):
        return ''
    return value.strip().lower().replace('-', '').replace('_', '').replace(' ', '')


def truncated_read(data, criteria_key):
    """The reason this body cannot answer the criterion, or None if it can.

    Host List Detection caps its reply at 1000 host records when the request sends no
    truncation_limit, and says so with <WARNING><CODE>1980</CODE><TEXT>N record limit
    exceeded...</TEXT><URL>...&id_min=...</URL> carrying the URL for the next batch (VM/PC API
    user guide p1127 for the default, p1143 for the warning). Nothing here follows that URL, so
    a body carrying the warning is a sample of the estate and not the estate: a count, a mean or
    a percentage over it is not a measurement of this customer and must not be reported as one.
    """
    try:
        response = data.get('HOST_LIST_VM_DETECTION_OUTPUT', {}) if isinstance(data, dict) else {}
        response = response.get('RESPONSE', {}) if isinstance(response, dict) else {}
        warnings = response.get('WARNING') if isinstance(response, dict) else None
    except Exception:
        # A body this cannot even read is not a body that says it was truncated, so fall through
        # to the behaviour already on main rather than answering for it. That path -- a read that
        # raises returning a graded number instead of a not-measured -- is F-ASM-05, a separate
        # finding with a separate fix, and this branch deliberately leaves it exactly as it was.
        return None
    if isinstance(warnings, dict):
        warnings = [warnings]
    if not isinstance(warnings, list):
        return None
    for warning in warnings:
        if not isinstance(warning, dict):
            continue
        code = str(warning.get('CODE', '')).strip()
        text = str(warning.get('TEXT', '')).strip()
        if code == TRUNCATION_WARNING_CODE or 'record limit exceeded' in text.lower():
            return ('Qualys truncated the host list (WARNING ' + (code or TRUNCATION_WARNING_CODE)
                    + ': ' + (text or 'record limit exceeded') + '), so this reply is a sample of '
                    'the estate rather than the estate, and ' + criteria_key
                    + ' was not measured.')
    return None


def evaluate(data):
    """Core evaluation logic."""
    try:
        hosts = data.get('HOST_LIST_VM_DETECTION_OUTPUT', {}).get('RESPONSE', {}).get('HOST_LIST', {}).get('HOST', [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        deltas = []
        for host in hosts:
            detections = host.get('DETECTION_LIST', {}).get('DETECTION', [])
            if isinstance(detections, dict):
                detections = [detections]
            for d in detections:
                if int(d.get('SEVERITY', 0)) >= 4 and detection_status(d) == 'fixed':
                    found = d.get('FIRST_FOUND_DATETIME', '')
                    fixed_dt = d.get('LAST_FIXED_DATETIME', '')
                    if found and fixed_dt:
                        t_found = datetime.fromisoformat(found.replace('Z', '+00:00'))
                        t_fixed = datetime.fromisoformat(fixed_dt.replace('Z', '+00:00'))
                        deltas.append((t_fixed - t_found).days)
        mttr = int(sum(deltas) / len(deltas)) if deltas else 0
        return {"meanTimeToRemediateCritical": str(mttr), "averageDays": mttr, "sampleSize": len(deltas)}
    except Exception as e:
        return {"meanTimeToRemediateCritical": "0", "error": str(e)}


def transform(input):
    criteriaKey = "meanTimeToRemediateCritical"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        truncated = truncated_read(data, criteriaKey)
        if truncated:
            return create_response(
                result={criteriaKey: None}, validation=validation,
                api_errors=[truncated], fail_reasons=[truncated],
                recommendations=['Send truncation_limit=0 on getVulnerabilities, as the sibling '
                                 'getHostList already does, or follow the WARNING URL, so the '
                                 'whole estate is read'],
                input_summary={criteriaKey: None, 'truncated': True})
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Qualys configuration for {criteriaKey}")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
