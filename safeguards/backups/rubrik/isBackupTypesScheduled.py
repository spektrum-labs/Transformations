"""
Transformation: isBackupTypesScheduled
Vendor: Rubrik  |  Category: Backup
Evaluates: Whether multiple backup schedule types (hourly, daily, weekly, monthly) are configured in Rubrik SLA Domains.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTypesScheduled", "vendor": "Rubrik", "category": "Backup"}
        }
    }


def check_schedule_type(freq_obj):
    if freq_obj is None:
        return False
    if not isinstance(freq_obj, dict):
        return False
    freq_val = freq_obj.get("frequency", freq_obj.get("basicSchedule", {}).get("frequency", 0))
    if isinstance(freq_val, dict):
        freq_val = freq_val.get("frequency", 0)
    return int(freq_val) > 0 if freq_val else False


def evaluate(data):
    try:
        sla_list = []
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                sla_list = data["data"]
            elif "slaDomains" in data and isinstance(data["slaDomains"], list):
                sla_list = data["slaDomains"]
            else:
                sla_list = [data]
        elif isinstance(data, list):
            sla_list = data

        if len(sla_list) == 0:
            return {"isBackupTypesScheduled": False, "error": "No SLA domains found in response"}

        schedule_types_found = []
        domains_with_multiple_types = 0
        total_domains_checked = len(sla_list)

        for domain in sla_list:
            if not isinstance(domain, dict):
                continue
            frequencies = domain.get("frequencies", domain.get("schedules", {}))
            if not isinstance(frequencies, dict):
                continue

            domain_types = []
            if check_schedule_type(frequencies.get("hourly")):
                domain_types.append("hourly")
            if check_schedule_type(frequencies.get("daily")):
                domain_types.append("daily")
            if check_schedule_type(frequencies.get("weekly")):
                domain_types.append("weekly")
            if check_schedule_type(frequencies.get("monthly")):
                domain_types.append("monthly")
            if check_schedule_type(frequencies.get("yearly")):
                domain_types.append("yearly")
            if check_schedule_type(frequencies.get("quarterly")):
                domain_types.append("quarterly")

            for t in domain_types:
                if t not in schedule_types_found:
                    schedule_types_found.append(t)

            if len(domain_types) >= 2:
                domains_with_multiple_types = domains_with_multiple_types + 1

        scheduled = len(schedule_types_found) >= 2

        return {
            "isBackupTypesScheduled": scheduled,
            "scheduledTypes": schedule_types_found,
            "scheduledTypeCount": len(schedule_types_found),
            "domainsWithMultipleTypes": domains_with_multiple_types,
            "totalDomainsChecked": total_domains_checked
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Multiple backup schedule types are configured in Rubrik SLA Domains")
            additional_findings.append("Scheduled types detected: " + ", ".join(extra_fields.get("scheduledTypes", [])))
            additional_findings.append("Domains with multiple types: " + str(extra_fields.get("domainsWithMultipleTypes", 0)))
        else:
            fail_reasons.append("Insufficient backup schedule types — fewer than 2 schedule types found across all SLA Domains")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure multiple frequency types (daily, weekly, monthly) in Rubrik SLA Domain policies to ensure comprehensive backup coverage")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"scheduledTypeCount": extra_fields.get("scheduledTypeCount", 0), "totalDomainsChecked": extra_fields.get("totalDomainsChecked", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
