"""
Transformation: requiredCoveragePercentage
Vendor: BeyondTrust Privileged Remote Access (PRA)  |  Category: Identity & Access Management
Evaluates: At least 80% of vault accounts are in a healthy, managed state
(account_state == "valid" AND assigned to a group policy). This represents the
percentage of privileged credentials that are actively brought under PRA management.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "BeyondTrust PRA", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    try:
        if isinstance(data, dict):
            accounts = data.get("accounts", data.get("items", data.get("results", [])))
        elif isinstance(data, list):
            accounts = data
        else:
            return {
                "requiredCoveragePercentage": False,
                "managedAccounts": 0,
                "totalAccounts": 0,
                "coveragePercent": 0.0,
                "reason": "Unexpected type"
            }

        total = len(accounts)
        if total == 0:
            return {
                "requiredCoveragePercentage": False,
                "managedAccounts": 0,
                "totalAccounts": 0,
                "coveragePercent": 0.0,
                "reason": "No vault accounts found"
            }

        managed = 0
        for account in accounts:
            if not isinstance(account, dict):
                continue
            state = str(account.get("account_state", "")).lower()
            policy_id = account.get("group_policy_id", account.get("policy_id"))
            has_policy = policy_id not in (None, "", 0)
            if state == "valid" and has_policy:
                managed += 1

        coverage = (managed / total) * 100
        return {
            "requiredCoveragePercentage": coverage >= COVERAGE_THRESHOLD,
            "managedAccounts": managed,
            "totalAccounts": total,
            "coveragePercent": round(coverage, 2)
        }
    except Exception as e:
        return {"requiredCoveragePercentage": False, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
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
            recommendations.append("Bring more privileged credentials under PRA vault management and assign them to a group policy")

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
