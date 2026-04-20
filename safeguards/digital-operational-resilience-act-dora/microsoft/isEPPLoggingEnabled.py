"""
Transformation: isEPPLoggingEnabled
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether endpoint protection and device management audit log records are being captured in Microsoft Entra ID directory audits.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def evaluate(data):
    try:
        records = data.get("value", [])
        total_records = len(records)
        epp_keywords = ["device", "endpoint", "intune", "mdm", "defender", "compliance", "manageddevice"]
        epp_record_count = 0
        for record in records:
            category = record.get("category", "").lower()
            activity = record.get("activityDisplayName", "").lower()
            logged_by = record.get("loggedByService", "").lower()
            is_epp_related = False
            for kw in epp_keywords:
                if kw in category or kw in activity or kw in logged_by:
                    is_epp_related = True
                    break
            if is_epp_related:
                epp_record_count = epp_record_count + 1
        is_logging_enabled = total_records > 0
        return {
            "isEPPLoggingEnabled": is_logging_enabled,
            "totalAuditRecords": total_records,
            "eppRelatedRecords": epp_record_count
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
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
            pass_reasons.append("Audit log records found confirming EPP-related logging is active")
            pass_reasons.append("Total audit records: " + str(extra_fields.get("totalAuditRecords", 0)) + ", EPP-related: " + str(extra_fields.get("eppRelatedRecords", 0)))
        else:
            fail_reasons.append("No audit log records found — EPP logging may not be active")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure AuditLog.Read.All permissions are granted and that Entra ID audit logging is enabled to capture device and endpoint management events")
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
