"""
Transformation: isAuditPlanActive
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether audit plans exist with defined schedules and recent audits have been completed or are in progress.
Source: GET /api/v2/audits
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditPlanActive", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if audit plans exist with schedules and recent completion."""
    try:
        audits = data.get("data", data.get("audits", data.get("results", [])))
        if not isinstance(audits, list):
            audits = [audits] if audits else []

        total_audits = len(audits)
        active_audits = 0
        completed_audits = 0
        planned_audits = 0
        audit_titles = []

        for audit in audits:
            if not isinstance(audit, dict):
                continue

            attrs = audit.get("attributes", audit)
            if not isinstance(attrs, dict):
                continue

            status = str(attrs.get("status", attrs.get("state", attrs.get("audit_status", "")))).lower()
            title = attrs.get("title", attrs.get("name", attrs.get("slug", "")))

            if status in ("in progress", "active", "in_progress", "started", "open"):
                active_audits = active_audits + 1
                if title:
                    audit_titles.append(str(title))
            elif status in ("completed", "closed", "finished", "done"):
                completed_audits = completed_audits + 1
            elif status in ("planned", "not started", "not_started", "draft", "scheduled"):
                planned_audits = planned_audits + 1
            else:
                # Count unrecognized statuses as active if title exists
                if title:
                    active_audits = active_audits + 1
                    audit_titles.append(str(title))

        has_audit_activity = active_audits > 0 or completed_audits > 0 or planned_audits > 0

        return {
            "isAuditPlanActive": has_audit_activity,
            "totalAudits": total_audits,
            "activeAudits": active_audits,
            "completedAudits": completed_audits,
            "plannedAudits": planned_audits,
            "auditTitles": audit_titles[:10]
        }
    except Exception as e:
        return {"isAuditPlanActive": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAuditPlanActive"
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(str(extra_fields.get("totalAudits", 0)) + " audit(s) found in ZenGRC")
            if extra_fields.get("activeAudits", 0) > 0:
                pass_reasons.append(str(extra_fields["activeAudits"]) + " audit(s) currently in progress")
            if extra_fields.get("completedAudits", 0) > 0:
                pass_reasons.append(str(extra_fields["completedAudits"]) + " audit(s) completed")
            if extra_fields.get("plannedAudits", 0) > 0:
                pass_reasons.append(str(extra_fields["plannedAudits"]) + " audit(s) planned/scheduled")
        else:
            fail_reasons.append("No audits found in ZenGRC")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create an audit plan with scheduled audits in ZenGRC")
            recommendations.append("Ensure audits are mapped to compliance programs and have defined scope")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalAudits": extra_fields.get("totalAudits", 0), "activeAudits": extra_fields.get("activeAudits", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
