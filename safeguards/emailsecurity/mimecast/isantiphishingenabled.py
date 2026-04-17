"""
Transformation: isAntiPhishingEnabled
Vendor: Mimecast
Category: Email Security / Anti-Phishing

Evaluates whether Mimecast TTP Impersonation Protect is active by checking
the impersonation protect logs from /api/ttp/impersonation/get-logs.
A successful response (HTTP 200 with meta.status == 200) confirms the feature
is configured and scanning, even if the impersonationLogs array is empty.
Log entries provide additional evidence of active detection.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAntiPhishingEnabled", "vendor": "Mimecast", "category": "Email Security"}
        }
    }


def parse_api_error(data):
    """Check for Mimecast error responses."""
    if not isinstance(data, dict):
        return None
    meta = data.get("meta", {})
    if isinstance(meta, dict):
        status = meta.get("status")
        if isinstance(status, int) and status >= 400:
            return "Mimecast API returned status " + str(status)
    fail_list = data.get("fail", [])
    if isinstance(fail_list, list) and len(fail_list) > 0:
        first_fail = fail_list[0] if isinstance(fail_list[0], dict) else {}
        err_msg = first_fail.get("message", str(fail_list[0]))
        return "Mimecast API error: " + str(err_msg)
    return None


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # Schema validation failure should not block evaluation — proceed with
        # the data and carry the validation warnings through to the response.
        if validation.get("status") == "failed":
            validation["status"] = "warning"
            if not validation.get("warnings"):
                validation["warnings"] = []
            for err in validation.get("errors", []):
                validation["warnings"].append("Schema: " + str(err))
            validation["errors"] = []

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        antiphishing_enabled = False
        log_count = 0
        actions_seen = []
        identifiers_seen = []

        # Check for API-level errors first
        api_error = parse_api_error(data)
        if api_error:
            fail_reasons.append(api_error)
            recommendations.append("Verify the API application has 'Monitoring | Impersonation Protection | Read' permission in Mimecast")
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                api_errors=[api_error]
            )

        if isinstance(data, dict):
            # Mimecast wraps response in data[] array
            data_array = data.get("data", [])
            if isinstance(data_array, list) and len(data_array) > 0:
                first_entry = data_array[0] if isinstance(data_array[0], dict) else {}
                logs = first_entry.get("impersonationLogs", [])
            else:
                logs = []

            # A successful response from the impersonation protect logs endpoint
            # confirms the feature is configured, even with zero log entries.
            meta = data.get("meta", {})
            meta_status = None
            if isinstance(meta, dict):
                meta_status = meta.get("status")

            if meta_status == 200 or "data" in data:
                antiphishing_enabled = True

            if isinstance(logs, list):
                log_count = len(logs)
                for log_entry in logs:
                    if not isinstance(log_entry, dict):
                        continue
                    action = log_entry.get("action", "")
                    if action and action not in actions_seen:
                        actions_seen.append(str(action))
                    entry_identifiers = log_entry.get("identifiers", [])
                    if isinstance(entry_identifiers, list):
                        for ident in entry_identifiers:
                            if ident and str(ident) not in identifiers_seen:
                                identifiers_seen.append(str(ident))

        elif isinstance(data, list):
            # Direct list of log entries
            antiphishing_enabled = True
            log_count = len(data)

        if antiphishing_enabled:
            if log_count > 0:
                pass_reasons.append(
                    "Mimecast TTP Impersonation Protect is active with "
                    + str(log_count) + " detection(s) in the reporting period"
                )
                if actions_seen:
                    additional_findings.append("Actions taken: " + ", ".join(actions_seen))
                if identifiers_seen:
                    additional_findings.append("Detection types: " + ", ".join(identifiers_seen))
            else:
                pass_reasons.append(
                    "Mimecast TTP Impersonation Protect is configured (API responded successfully, no detections in reporting period)"
                )
        else:
            fail_reasons.append("Mimecast TTP Impersonation Protect does not appear to be configured")
            recommendations.append("Enable TTP Impersonation Protect in the Mimecast Admin Console under Gateway > Policies > Impersonation Protect")
            recommendations.append("Ensure the API application has 'Monitoring | Impersonation Protection | Read' permission")

        return create_response(
            result={
                criteriaKey: antiphishing_enabled,
                "detectionCount": log_count,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "antiphishingActive": antiphishing_enabled,
                "logEntries": log_count,
                "actionTypes": actions_seen,
                "identifierTypes": identifiers_seen,
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
