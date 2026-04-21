"""
Transformation: isContinuousDiscoveryEnabled
Vendor: ProjectDiscovery OS  |  Category: soc-2-type-ii-comprehensive-non-privacy
Evaluates: Whether automated asset enumeration and discovery schedules are configured
           and active in ProjectDiscovery Cloud Platform, indicating continuous external
           attack surface monitoring is in place.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_iter in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isContinuousDiscoveryEnabled", "vendor": "ProjectDiscovery OS", "category": "soc-2-type-ii-comprehensive-non-privacy"}
        }
    }


def get_list_data(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        schedules = get_list_data(data)
        total_schedules = len(schedules)

        if total_schedules == 0:
            out = {}
            out["isContinuousDiscoveryEnabled"] = False
            out["totalSchedules"] = 0
            out["activeSchedules"] = 0
            out["error"] = "No enumeration schedules found"
            return out

        active_count = 0
        schedule_names = []
        frequencies = []

        for schedule in schedules:
            if not isinstance(schedule, dict):
                continue

            is_active = False
            status = str(schedule.get("status", schedule.get("enabled", ""))).lower()
            if status in ["active", "enabled", "true", "running", "scheduled"]:
                is_active = True
            elif status == "" and schedule.get("id", None) is not None:
                is_active = True

            if is_active:
                active_count = active_count + 1

            name = str(schedule.get("name", schedule.get("id", "")))
            if name and name not in schedule_names:
                schedule_names.append(name)

            freq = str(schedule.get("frequency", schedule.get("interval", schedule.get("cron", ""))))
            if freq and freq not in frequencies:
                frequencies.append(freq)

        is_enabled = active_count > 0 or total_schedules > 0

        out = {}
        out["isContinuousDiscoveryEnabled"] = is_enabled
        out["totalSchedules"] = total_schedules
        out["activeSchedules"] = active_count
        out["scheduleNames"] = schedule_names
        out["scheduledFrequencies"] = frequencies
        return out
    except Exception as e:
        out = {}
        out["isContinuousDiscoveryEnabled"] = False
        out["error"] = str(e)
        return out


def transform(input):
    criteriaKey = "isContinuousDiscoveryEnabled"
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            pass_reasons.append("Total enumeration schedules configured: " + str(eval_result.get("totalSchedules", 0)))
            if eval_result.get("activeSchedules", 0) > 0:
                pass_reasons.append("Active schedules: " + str(eval_result.get("activeSchedules", 0)))
            freqs = eval_result.get("scheduledFrequencies", [])
            if freqs:
                additional_findings.append("Scheduled frequencies: " + ", ".join(freqs))
            names = eval_result.get("scheduleNames", [])
            if names:
                additional_findings.append("Schedule names: " + ", ".join(names))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure at least one enumeration schedule under Assets > Enumerations in the ProjectDiscovery Cloud Platform")
            recommendations.append("Enable automatic scheduling to ensure continuous asset discovery runs without manual intervention")

        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=result_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
