"""
Transformation: isAuditLoggingEnabled
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether audit logging is active for the tenant by confirming directory audit log records exist.
"""
import json
from datetime import datetime


def extract_input(input_data):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def evaluate(data):
    try:
        records = data.get("value", [])
        record_count = len(records)
        is_enabled = record_count > 0
        most_recent = ""
        if record_count > 0:
            most_recent = records[0].get("activityDateTime", "")
        return {
            "isAuditLoggingEnabled": is_enabled,
            "auditRecordCount": record_count,
            "mostRecentRecord": most_recent
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Directory audit log records exist confirming audit logging is active")
            pass_reasons.append("Audit records found: " + str(extra_fields.get("auditRecordCount", 0)))
            if extra_fields.get("mostRecentRecord"):
                pass_reasons.append("Most recent record: " + str(extra_fields.get("mostRecentRecord", "")))
        else:
            fail_reasons.append("No directory audit log records found — audit logging may not be active")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Entra ID audit logging is enabled and that the integration has Reports.Read.All and AuditLog.Read.All permissions")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=summary_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
