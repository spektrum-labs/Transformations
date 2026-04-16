"""
Transformation: isPasswordAutoManagementEnabled
Vendor: BeyondTrust Privileged Remote Access (PRA)  |  Category: Identity & Access Management
Evaluates: At least 80% of vault accounts have automatic password rotation enabled.
Checks PRA vault account fields `automatic_password_rotation` (generic_managed type)
or `rotation_interval_in_days` > 0 as evidence of auto-rotation.
"""
import json
from datetime import datetime

COVERAGE_THRESHOLD = 80.0


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPasswordAutoManagementEnabled", "vendor": "BeyondTrust PRA", "category": "Identity & Access Management"}
        }
    }


def _is_truthy(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1")
    if isinstance(val, (int, float)):
        return val > 0
    return False


def evaluate(data):
    try:
        if isinstance(data, dict):
            accounts = data.get("accounts", data.get("items", data.get("results", [])))
        elif isinstance(data, list):
            accounts = data
        else:
            return {
                "isPasswordAutoManagementEnabled": False,
                "automanagedCount": 0,
                "totalAccounts": 0,
                "coveragePercent": 0.0,
                "reason": "Unexpected type"
            }

        total = len(accounts)
        if total == 0:
            return {
                "isPasswordAutoManagementEnabled": False,
                "automanagedCount": 0,
                "totalAccounts": 0,
                "coveragePercent": 0.0,
                "reason": "No vault accounts found"
            }

        auto_count = 0
        for account in accounts:
            if not isinstance(account, dict):
                continue
            rotation_flag = account.get("automatic_password_rotation")
            rotation_interval = account.get("rotation_interval_in_days", 0)
            if _is_truthy(rotation_flag) or (isinstance(rotation_interval, (int, float)) and rotation_interval > 0):
                auto_count += 1

        coverage = (auto_count / total) * 100
        return {
            "isPasswordAutoManagementEnabled": coverage >= COVERAGE_THRESHOLD,
            "automanagedCount": auto_count,
            "totalAccounts": total,
            "coveragePercent": round(coverage, 2)
        }
    except Exception as e:
        return {"isPasswordAutoManagementEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPasswordAutoManagementEnabled"
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

        pass_reasons, fail_reasons, recommendations = [], [], []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed (threshold: {COVERAGE_THRESHOLD}%)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable automatic_password_rotation on vault accounts (account type must support rotation, e.g. generic_managed, linux, windows)")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
