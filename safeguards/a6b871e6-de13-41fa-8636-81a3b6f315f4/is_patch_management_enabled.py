"""
Transformation: isPatchManagementEnabled
Vendor: Qualys
Category: Security / Attack Surface Management

Evaluates whether patch management is enabled by querying the Qualys
Host List VM Detection API filtered by is_patchable=1 and status=Fixed.
If any hosts with Fixed (patched) detections are returned, patch
management is considered enabled.

Expected response structure:
{
    "HOST_LIST_VM_DETECTION_OUTPUT": {
        "RESPONSE": {
            "DATETIME": "2026-03-19T16:53:03Z",
            "HOST_LIST": {              # absent when no patched hosts
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


# Same reply helpers as safeguards/asm/qualys/patchcompliancepercentage.py; keep them in step.
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



def extract_hosts(response):
    """HOST records from a detection RESPONSE; Qualys omits HOST_LIST when nothing matched."""
    host_list = response.get("HOST_LIST", None)
    if host_list is None:
        return [], response.get("DATETIME", "")

    hosts = host_list.get("HOST", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    return hosts, response.get("DATETIME", "")


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


NOT_READ = ("Spektrum's Qualys read does not yet include patched detections, so patch management "
            "could not be checked.")


def count_fixed(hosts):
    """Fixed detections across all hosts: a host listed with only open rows proves no patching."""
    total = 0
    for host in hosts:
        detection_list = host.get("DETECTION_LIST", {}) if isinstance(host, dict) else {}
        if not isinstance(detection_list, dict):
            continue
        detections = detection_list.get("DETECTION", [])
        if isinstance(detections, dict):
            detections = [detections]
        if not isinstance(detections, list):
            continue
        total = total + len([d for d in detections if isinstance(d, dict) and status_token(d.get("STATUS", "")) == "fixed"])
    return total


def transform(input):
    criteriaKey = "isPatchManagementEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))]
            )

        # Check for integration execution errors
        if isinstance(data, dict) and "error" in data and "message" in data:
            if isinstance(data["message"], str) and data["message"].startswith("Integration execution error"):
                return create_response(
                    result={criteriaKey: False},
                    validation=validation,
                    fail_reasons=["Error communicating with Qualys API"],
                    recommendations=["Verify the Qualys API credentials and base URL are correct"]
                )

        response = detection_response(data)
        if response is None:
            # The workflow feeds this key getHostList, whose reply has no detection list, and an error body has
            # none either: nothing was measured, and the read is ours to fix.
            return not_measured(criteriaKey, NOT_READ, "not_measured", validation=validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        hosts, response_datetime = extract_hosts(response)
        host_count = len(hosts)
        detection_count = count_fixed(hosts)

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

        additional_findings = []
        if host_count > 0:
            statuses = {}
            for host in hosts:
                detection_list = host.get("DETECTION_LIST", {})
                if not detection_list:
                    continue
                detections = detection_list.get("DETECTION", [])
                if isinstance(detections, dict):
                    detections = [detections]
                for det in detections:
                    status = det.get("STATUS", "Unknown")
                    count = statuses.get(status, 0)
                    statuses[status] = count + 1

            for status_name in statuses:
                additional_findings.append({
                    "metric": f"patchableDetections_{status_name}",
                    "value": statuses[status_name],
                    "reason": f"{statuses[status_name]} patchable detection(s) with status '{status_name}'"
                })

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
                "patchedDetectionCount": detection_count,
                "hasHostList": host_count > 0
            }
        )

    except json.JSONDecodeError as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [f"Invalid JSON: {str(e)}"], "warnings": []},
            fail_reasons=["Could not parse input as valid JSON"]
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
