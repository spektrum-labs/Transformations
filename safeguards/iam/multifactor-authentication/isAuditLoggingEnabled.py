"""
Transformation: isAuditLoggingEnabled
Vendor: Multifactor Authentication  |  Category: iam
Evaluates: Confirm that authentication audit logs are enabled and accessible via the
           Duo Admin API. A successful API response containing authlogs data (or an
           accessible endpoint with OK stat) indicates that audit logging is active.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
                "vendor": "Multifactor Authentication",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    try:
        stat = data.get("stat", "")
        authlogs = data.get("authlogs", None)
        metadata = data.get("metadata", {})

        stat_ok = stat == "OK"
        authlogs_key_present = authlogs is not None
        log_count = len(authlogs) if isinstance(authlogs, list) else 0

        is_enabled = stat_ok or authlogs_key_present

        total_objects = metadata.get("total_objects", log_count)

        return {
            "isAuditLoggingEnabled": is_enabled,
            "statOk": stat_ok,
            "authLogsKeyPresent": authlogs_key_present,
            "recentLogCount": log_count,
            "totalObjects": total_objects if total_objects else log_count,
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
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Audit logging is enabled and accessible via the Duo Admin API")
            if eval_result.get("statOk", False):
                pass_reasons.append("API returned OK status confirming log endpoint is active")
            pass_reasons.append("Recent log count retrieved: " + str(eval_result.get("recentLogCount", 0)))
        else:
            fail_reasons.append("Audit logging does not appear to be enabled or is inaccessible")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that the Duo Admin API has 'Grant read log' permission enabled")
            recommendations.append("Confirm that authentication logging is active in the Duo Admin Panel")
        if eval_result.get("recentLogCount", 0) == 0 and result_value:
            additional_findings.append("No recent authentication log entries were returned; logging is enabled but may have no recent activity")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "statOk": eval_result.get("statOk", False),
                "recentLogCount": eval_result.get("recentLogCount", 0),
                "totalObjects": eval_result.get("totalObjects", 0)
            })
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
