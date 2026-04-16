"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: IAM
Evaluates: Checks that administrator audit logging is enabled and events are being captured
via the Duo Admin API GET /admin/v2/logs/administrator endpoint. Passes when log entries
are present in the response, confirming audit events are being recorded.
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
                "transformationId": "isAuditLoggingEnabled",
                "vendor": "Duo",
                "category": "IAM"
            }
        }
    }


def evaluate(data):
    """
    Core evaluation logic for isAuditLoggingEnabled.
    The getAdministratorLogs returnSpec extracts 'response' (dict with 'items' list)
    and 'metadata'. After extract_input unwraps the 'response' dict wrapper, data
    will be: {"items": [...log entries...], "metadata": {...}}.
    Falls back to checking a raw list if that shape is encountered instead.
    """
    try:
        items = []

        if isinstance(data, list):
            # Already a flat list of log entries
            items = data
        elif isinstance(data, dict):
            # Try {"items": [...]} shape (v2 logs response body)
            candidate = data.get("items", None)
            if isinstance(candidate, list):
                items = candidate
            else:
                # Try nested {"response": {"items": [...]}} in case unwrapping did not occur
                nested = data.get("response", None)
                if isinstance(nested, dict):
                    nested_items = nested.get("items", [])
                    if isinstance(nested_items, list):
                        items = nested_items
                elif isinstance(nested, list):
                    items = nested

        total_log_entries = len(items)
        is_audit_logging_enabled = total_log_entries > 0

        return {
            "isAuditLoggingEnabled": is_audit_logging_enabled,
            "totalLogEntries": total_log_entries
        }
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAuditLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "totalLogEntries": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        total_log_entries = eval_result.get("totalLogEntries", 0)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Administrator audit logging is enabled and capturing events")
            pass_reasons.append("Total log entries retrieved: " + str(total_log_entries))
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("No administrator audit log entries found in response")
                fail_reasons.append("Audit logging may be disabled or no events have been recorded")
            recommendations.append("Verify that the Duo Admin API application has 'Grant read log' permission")
            recommendations.append("Confirm administrator actions are being taken and logs are being generated")
            recommendations.append("Review Duo account settings to ensure audit logging is active")

        if total_log_entries > 0:
            additional_findings.append("Log entries present confirming audit trail is active")

        return create_response(
            result={criteriaKey: result_value, "totalLogEntries": total_log_entries},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalLogEntries": total_log_entries, criteriaKey: result_value}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "totalLogEntries": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
