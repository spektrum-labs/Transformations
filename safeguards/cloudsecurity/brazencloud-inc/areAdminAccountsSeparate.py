"""
Transformation: areAdminAccountsSeparate
Vendor: BrazenCloud, Inc.  |  Category: cloudsecurity
Evaluates: Whether administrative accounts are separated from standard user accounts,
           based on BrazenCloud runner and endpoint data (getRunners).
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
                "transformationId": "areAdminAccountsSeparate",
                "vendor": "BrazenCloud, Inc.",
                "category": "cloudsecurity"
            }
        }
    }


def to_searchable(val):
    if isinstance(val, str):
        return val.lower()
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val).lower()
        except Exception:
            return str(val).lower()
    return str(val).lower()


def extract_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        candidates = ["data", "results", "items", "runners"]
        for key in candidates:
            val = data.get(key)
            if isinstance(val, list):
                return val
    return []


def is_admin_runner(item):
    admin_indicators = [
        "admin", "administrator", "privileged", "superuser", "sysadmin",
        "domainadmin", "globaladmin", "cloudadmin", "secadmin", "itadmin"
    ]
    name_val = to_searchable(item.get("name", ""))
    tags_val = to_searchable(item.get("tags", []))
    groups_val = to_searchable(item.get("groups", []))
    role_val = to_searchable(item.get("role", item.get("runnerType", "")))
    combined = name_val + " " + tags_val + " " + groups_val + " " + role_val
    for indicator in admin_indicators:
        if indicator in combined:
            return True
    return False


def is_standard_runner(item):
    standard_indicators = [
        "standard", "user", "endpoint", "workstation", "client", "desktop",
        "regular", "nonprivileged", "normaluser"
    ]
    name_val = to_searchable(item.get("name", ""))
    tags_val = to_searchable(item.get("tags", []))
    groups_val = to_searchable(item.get("groups", []))
    role_val = to_searchable(item.get("role", item.get("runnerType", "")))
    combined = name_val + " " + tags_val + " " + groups_val + " " + role_val
    for indicator in standard_indicators:
        if indicator in combined:
            return True
    return False


def evaluate(data):
    try:
        items = extract_items(data)
        total_items = len(items)

        if total_items == 0:
            return {
                "areAdminAccountsSeparate": False,
                "totalRunners": 0,
                "adminRunnerCount": 0,
                "standardRunnerCount": 0,
                "mixedRunnerCount": 0,
                "evaluationNote": "No runner data available to evaluate admin account separation"
            }

        admin_runners = []
        standard_runners = []
        mixed_runners = []
        separation_indicators = []

        for item in items:
            if not isinstance(item, dict):
                continue

            item_id = str(item.get("id", item.get("name", "unknown")))
            item_is_admin = is_admin_runner(item)
            item_is_standard = is_standard_runner(item)

            is_separated = item.get("isSeparated", item.get("accountSeparated", None))
            if is_separated is True:
                separation_indicators.append(item_id)

            output_val = to_searchable(item.get("output", item.get("data", item.get("result", ""))))
            if "adminseparate" in output_val or "separateadmin" in output_val or "accountseparation" in output_val:
                separation_indicators.append(item_id)

            if item_is_admin and item_is_standard:
                mixed_runners.append(item_id)
            elif item_is_admin:
                admin_runners.append(item_id)
            elif item_is_standard:
                standard_runners.append(item_id)

        has_separation_evidence = len(separation_indicators) > 0
        has_clean_separation = (
            len(admin_runners) > 0 and
            len(standard_runners) > 0 and
            len(mixed_runners) == 0
        )

        are_separate = has_separation_evidence or has_clean_separation

        return {
            "areAdminAccountsSeparate": are_separate,
            "totalRunners": total_items,
            "adminRunnerCount": len(admin_runners),
            "standardRunnerCount": len(standard_runners),
            "mixedRunnerCount": len(mixed_runners),
            "separationIndicatorCount": len(separation_indicators),
            "evaluationNote": "Evaluated from BrazenCloud runner metadata for admin account separation indicators"
        }
    except Exception as e:
        return {"areAdminAccountsSeparate": False, "error": str(e)}


def transform(input):
    criteriaKey = "areAdminAccountsSeparate"
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

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Administrative accounts are confirmed as separate from standard user accounts")
            pass_reasons.append("Runner data indicates distinct admin and standard account classifications")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Administrative account separation is not confirmed from runner data")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Ensure dedicated administrative accounts are used exclusively for privileged tasks and are not shared with daily-use accounts"
            )
            recommendations.append(
                "Tag or group BrazenCloud runners by account type (admin vs standard) to enable automated separation checks"
            )
            recommendations.append(
                "Run BrazenCloud account enumeration jobs to produce structured output distinguishing admin from standard accounts"
            )

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
