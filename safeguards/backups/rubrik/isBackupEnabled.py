"""
Transformation: isBackupEnabled
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether SLA domains exist with at least one configured snapshot schedule
(daily, weekly, monthly, or yearly), indicating automated backup policies are active in RSC.
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
                "transformationId": "isBackupEnabled",
                "vendor": "Rubrik",
                "category": "Backup"
            }
        }
    }


def has_active_schedule(schedule):
    """Return True if at least one schedule type has a basicSchedule with frequency > 0."""
    if not isinstance(schedule, dict):
        return False
    for stype in ["daily", "weekly", "monthly", "yearly"]:
        entry = schedule.get(stype)
        if not isinstance(entry, dict):
            continue
        basic = entry.get("basicSchedule")
        if isinstance(basic, dict):
            freq = basic.get("frequency")
            if freq is not None and freq > 0:
                return True
    return False


def evaluate(data):
    try:
        nodes = []
        raw_nodes = data.get("nodes", [])
        if isinstance(raw_nodes, list):
            for node in raw_nodes:
                if isinstance(node, dict) and "snapshotSchedule" in node:
                    nodes.append(node)
        if not nodes:
            sla_data = data.get("slaDomains", {})
            if isinstance(sla_data, dict):
                raw_nodes = sla_data.get("nodes", [])
                if isinstance(raw_nodes, list):
                    nodes = raw_nodes

        total_domains = len(nodes)
        enabled_domains = []
        for node in nodes:
            schedule = node.get("snapshotSchedule")
            if has_active_schedule(schedule):
                enabled_domains.append(node.get("name", "unknown"))

        enabled_count = len(enabled_domains)
        is_enabled = enabled_count > 0

        return {
            "isBackupEnabled": is_enabled,
            "totalSlaDomains": total_domains,
            "enabledSlaDomains": enabled_count,
            "enabledDomainNames": enabled_domains
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabled"
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
        findings = []
        if result_value:
            pass_reasons.append(
                "Backup is enabled: " + str(eval_result.get("enabledSlaDomains", 0)) +
                " SLA domain(s) have active snapshot schedules"
            )
            names = eval_result.get("enabledDomainNames", [])
            if names:
                findings.append("Active SLA domains: " + ", ".join(names))
        else:
            fail_reasons.append("No SLA domains with active snapshot schedules were found in RSC")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Create at least one SLA domain in Rubrik Security Cloud with a configured "
                "snapshot schedule (daily, weekly, monthly, or yearly) to enable automated backups"
            )
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={
                "totalSlaDomains": eval_result.get("totalSlaDomains", 0),
                "enabledSlaDomains": eval_result.get("enabledSlaDomains", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
