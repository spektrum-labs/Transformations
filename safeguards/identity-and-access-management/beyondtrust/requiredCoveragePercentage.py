"""
Transformation: requiredCoveragePercentage
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: The percentage of managed systems that have at least one managed account.
Returns a numeric 0-100 integer representing coverage.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"requiredCoveragePercentage": None, "error": "required fields missing from API response: managedSystems, managedAccounts"}

        managed_systems = data.get("managedSystems", data.get("ManagedSystems", []))
        managed_accounts = data.get("managedAccounts", data.get("ManagedAccounts", []))

        if not isinstance(managed_systems, list):
            managed_systems = []
        if not isinstance(managed_accounts, list):
            managed_accounts = []

        total_systems = len(managed_systems)
        if total_systems == 0:
            return {
                "requiredCoveragePercentage": 0,
                "coveredSystems": 0,
                "totalSystems": 0,
                "reason": "No managed systems found"
            }

        system_ids_with_accounts = {}
        for account in managed_accounts:
            system_id = account.get("ManagedSystemID")
            if system_id is not None:
                system_ids_with_accounts[system_id] = True

        covered = 0
        for system in managed_systems:
            system_id = system.get("ManagedSystemID")
            if system_id is not None and system_ids_with_accounts.get(system_id, False):
                covered = covered + 1

        coverage = round((covered / total_systems) * 100)

        return {
            "requiredCoveragePercentage": coverage,
            "coveredSystems": covered,
            "totalSystems": total_systems
        }
    except Exception as e:
        return {"requiredCoveragePercentage": None, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, None)
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value is not None and "error" not in eval_result:
            pass_reasons.append(criteriaKey + ": " + str(result_value) + "%")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " could not be computed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Review vendor configuration for " + criteriaKey)
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: None}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
