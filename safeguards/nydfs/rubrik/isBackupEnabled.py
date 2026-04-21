"""
Transformation: isBackupEnabled
Vendor: Rubrik  |  Category: nydfs / Backups
Evaluates: Whether active SLA Domain backup policies are defined in Rubrik Security Cloud.
Checks that at least one non-default SLA domain with a configured snapshotSchedule exists.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabled", "vendor": "Rubrik", "category": "nydfs/Backups"}
        }
    }


def has_snapshot_schedule(domain):
    schedule = domain.get("snapshotSchedule", None)
    if schedule is None:
        return False
    if schedule.get("daily", None) is not None:
        return True
    if schedule.get("weekly", None) is not None:
        return True
    if schedule.get("monthly", None) is not None:
        return True
    if schedule.get("yearly", None) is not None:
        return True
    return False


def evaluate(data):
    try:
        sla_domains = data.get("data", [])
        if not isinstance(sla_domains, list):
            sla_domains = []

        total_domains = len(sla_domains)
        active_domains = []

        for domain in sla_domains:
            is_default = domain.get("isDefault", False)
            if is_default:
                continue
            if has_snapshot_schedule(domain):
                active_domains.append(domain.get("name", "unnamed"))

        active_count = len(active_domains)
        result = active_count > 0

        return {
            "isBackupEnabled": result,
            "totalSlaDomains": total_domains,
            "activeBackupPolicies": active_count,
            "activePolicyNames": active_domains
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalSlaDomains", 0)
        active = eval_result.get("activeBackupPolicies", 0)
        names = eval_result.get("activePolicyNames", [])

        additional_findings.append("Total SLA domains found: " + str(total))
        additional_findings.append("Active non-default SLA domains with snapshot schedule: " + str(active))

        if result_value:
            pass_reasons.append("At least one active non-default SLA domain with a configured snapshot schedule was found.")
            pass_reasons.append("Active policies: " + ", ".join(names))
        else:
            if total == 0:
                fail_reasons.append("No SLA domains were returned by the Rubrik API.")
            else:
                fail_reasons.append("No non-default SLA domains with a configured snapshotSchedule were found.")
            recommendations.append("Define and activate at least one SLA domain with a snapshot schedule in Rubrik Security Cloud.")
            recommendations.append("Assign SLA domains to objects to ensure backup policies are actively protecting data.")

        extra_fields = {
            "totalSlaDomains": total,
            "activeBackupPolicies": active,
            "activePolicyNames": names
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"slaDomainCount": total, "activeCount": active}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
