"""
Transformation: isBackupTypesScheduled
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether SLA domains have multiple backup schedule types configured
(e.g. daily AND weekly or monthly), confirming a layered RPO strategy is in place.
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
                "transformationId": "isBackupTypesScheduled",
                "vendor": "Rubrik",
                "category": "Backup"
            }
        }
    }


def count_schedule_types(schedule):
    """Count how many schedule types (daily/weekly/monthly/yearly) are active."""
    if not isinstance(schedule, dict):
        return 0
    count = 0
    for stype in ["daily", "weekly", "monthly", "yearly"]:
        entry = schedule.get(stype)
        if not isinstance(entry, dict):
            continue
        basic = entry.get("basicSchedule")
        if isinstance(basic, dict):
            freq = basic.get("frequency")
            if freq is not None and freq > 0:
                count = count + 1
    return count


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
        multi_type_domains = []
        single_type_domains = []

        for node in nodes:
            schedule = node.get("snapshotSchedule")
            type_count = count_schedule_types(schedule)
            name = node.get("name", "unknown")
            if type_count >= 2:
                multi_type_domains.append(name)
            elif type_count == 1:
                single_type_domains.append(name)

        multi_count = len(multi_type_domains)
        is_scheduled = multi_count > 0

        return {
            "isBackupTypesScheduled": is_scheduled,
            "totalSlaDomains": total_domains,
            "multiTypeScheduledDomains": multi_count,
            "multiTypeDomainNames": multi_type_domains,
            "singleTypeOnlyDomains": len(single_type_domains)
        }
    except Exception as e:
        return {"isBackupTypesScheduled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTypesScheduled"
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
                "Multiple backup schedule types are configured: " +
                str(eval_result.get("multiTypeScheduledDomains", 0)) +
                " SLA domain(s) have 2 or more schedule types (daily/weekly/monthly/yearly)"
            )
            names = eval_result.get("multiTypeDomainNames", [])
            if names:
                findings.append("Layered-schedule SLA domains: " + ", ".join(names))
        else:
            fail_reasons.append(
                "No SLA domains with multiple backup schedule types were found; "
                "a layered RPO strategy is not confirmed"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if eval_result.get("singleTypeOnlyDomains", 0) > 0:
                findings.append(
                    str(eval_result.get("singleTypeOnlyDomains", 0)) +
                    " SLA domain(s) have only a single schedule type configured"
                )
            recommendations.append(
                "Configure at least two schedule types (e.g. daily AND weekly) on one or more "
                "SLA domains to implement a layered recovery-point-objective strategy"
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
                "multiTypeScheduledDomains": eval_result.get("multiTypeScheduledDomains", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
