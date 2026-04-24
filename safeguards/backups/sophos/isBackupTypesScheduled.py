"""
Transformation: isBackupTypesScheduled
Vendor: Sophos  |  Category: Backups
Evaluates: Reviews endpoint protection policies to determine whether scheduled
backup types (full, incremental) are defined and actively configured.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTypesScheduled", "vendor": "Sophos", "category": "Backups"}
        }
    }


def settings_contains_schedule(settings):
    if not settings:
        return False
    for key in settings:
        key_lower = key.lower()
        if "schedule" in key_lower or "backup" in key_lower or "interval" in key_lower or "frequency" in key_lower:
            return True
        val = settings[key]
        if isinstance(val, dict):
            if settings_contains_schedule(val):
                return True
        if isinstance(val, str):
            val_lower = val.lower()
            if "schedule" in val_lower or "backup" in val_lower or "full" in val_lower or "incremental" in val_lower:
                return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {"isBackupTypesScheduled": False, "totalPolicies": 0, "scheduledPolicies": 0, "scheduledPolicyNames": []}

        total = len(items)
        scheduled_count = 0
        scheduled_names = []
        enabled_count = 0

        for policy in items:
            name = policy.get("name", "")
            name_lower = name.lower()
            ptype = policy.get("type", "").lower()
            settings = policy.get("settings", {})
            enabled = policy.get("enabled", False)

            if enabled:
                enabled_count = enabled_count + 1

            has_schedule = False
            if "backup" in name_lower or "schedule" in name_lower:
                has_schedule = True
            if "backup" in ptype or "schedule" in ptype:
                has_schedule = True
            if not has_schedule and settings_contains_schedule(settings):
                has_schedule = True

            if has_schedule and enabled:
                scheduled_count = scheduled_count + 1
                scheduled_names.append(name if name else "unnamed-policy")

        result = scheduled_count > 0

        return {
            "isBackupTypesScheduled": result,
            "totalPolicies": total,
            "enabledPolicies": enabled_count,
            "scheduledPolicies": scheduled_count,
            "scheduledPolicyNames": scheduled_names
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

        if result_value:
            sc = extra_fields.get("scheduledPolicies", 0)
            pass_reasons.append("Scheduled backup policy types found: " + str(sc))
            names = extra_fields.get("scheduledPolicyNames", [])
            if names:
                pass_reasons.append("Policies with scheduling: " + ", ".join(names))
        else:
            fail_reasons.append("No enabled policies with scheduled backup types were found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure scheduled backup policies (full, incremental) within Sophos Central endpoint protection")
            recommendations.append("Ensure backup schedule settings are enabled and assigned to endpoint groups")

        result_dict = {"isBackupTypesScheduled": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": extra_fields.get("totalPolicies", 0), "scheduledPolicies": extra_fields.get("scheduledPolicies", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
