"""
Transformation: isBackupLoggingEnabled
Vendor: CrashPlan  |  Category: nydfs
Evaluates: Whether CrashPlan audit logging is active and generating backup-related events,
confirmed by a non-empty auditEvents list from the AuditLog resource.
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
                "transformationId": "isBackupLoggingEnabled",
                "vendor": "CrashPlan",
                "category": "nydfs"
            }
        }
    }


def evaluate(data):
    try:
        audit_events = data.get("auditEvents", [])
        total_count = data.get("totalCount", len(audit_events))
        event_count = len(audit_events)
        is_logging_enabled = event_count > 0
        event_types = []
        for event in audit_events:
            etype = event.get("type", event.get("eventType", event.get("action", "")))
            if etype and etype not in event_types:
                event_types.append(etype)
        return {
            "isBackupLoggingEnabled": is_logging_enabled,
            "auditEventCount": event_count,
            "totalEventCount": total_count,
            "uniqueEventTypes": len(event_types),
            "observedEventTypes": event_types
        }
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"
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
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        event_count_str = str(eval_result.get("auditEventCount", 0))
        total_count_str = str(eval_result.get("totalEventCount", 0))
        unique_types_str = str(eval_result.get("uniqueEventTypes", 0))
        if result_value:
            pass_reasons.append("CrashPlan audit logging is active and producing backup-related events")
            pass_reasons.append("Audit events retrieved: " + event_count_str + " (total on record: " + total_count_str + ")")
            pass_reasons.append("Unique event types observed: " + unique_types_str)
            observed = eval_result.get("observedEventTypes", [])
            if observed:
                additional_findings.append("Event types: " + ", ".join([str(t) for t in observed]))
        else:
            fail_reasons.append("No audit events found — CrashPlan audit logging may not be active or configured")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that audit logging is enabled in the CrashPlan org configuration")
            recommendations.append("Confirm the API client has the AuditLog read permission assigned")
            recommendations.append("Check that the CrashPlan console has audit event retention configured")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "auditEventCount": eval_result.get("auditEventCount", 0),
                "totalEventCount": eval_result.get("totalEventCount", 0),
                "uniqueEventTypes": eval_result.get("uniqueEventTypes", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
