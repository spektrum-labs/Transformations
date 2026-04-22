"""
Transformation: isEmailLoggingConfigured
Vendor: Microsoft  |  Category: emailsecurity
Evaluates: Verifies that directory audit logging is active by confirming audit log entries are present in the directoryAudits feed.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEmailLoggingConfigured", "vendor": "Microsoft", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        audit_entries = data.get("value", [])
        if not audit_entries:
            nested = data.get("getAuditLogs", {})
            if isinstance(nested, dict):
                audit_entries = nested.get("value", [])
        if not isinstance(audit_entries, list):
            audit_entries = []
        total_entries = len(audit_entries)
        is_configured = total_entries > 0
        categories = []
        services = []
        for entry in audit_entries:
            cat = entry.get("category", "")
            svc = entry.get("loggedByService", "")
            if cat and cat not in categories:
                categories.append(cat)
            if svc and svc not in services:
                services.append(svc)
        return {
            "isEmailLoggingConfigured": is_configured,
            "auditEntryCount": total_entries,
            "loggedCategories": ", ".join(categories) if categories else "None",
            "loggedServices": ", ".join(services) if services else "None"
        }
    except Exception as e:
        return {"isEmailLoggingConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEmailLoggingConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Audit log entries are present, confirming logging is active")
            pass_reasons.append("Audit entry count: " + str(eval_result.get("auditEntryCount", 0)))
        else:
            fail_reasons.append("No audit log entries found; logging may not be configured or active")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Microsoft Entra audit logging is enabled and the integration has AuditLog.Read.All permission")
        merged_result = {criteriaKey: result_value}
        for k in extra_fields:
            merged_result[k] = extra_fields[k]
        return create_response(
            result=merged_result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={"auditEntryCount": eval_result.get("auditEntryCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
