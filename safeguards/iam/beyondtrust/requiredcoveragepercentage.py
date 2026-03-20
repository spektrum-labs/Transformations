"""
Transformation: requiredCoveragePercentage
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: What percentage of managed systems have at least one managed account
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
    """Core evaluation logic extracted from doc transform."""
    try:
        # Extract managed systems and accounts from merged payload
        if isinstance(data, dict):
            managed_systems = data.get("managedSystems", data.get("ManagedSystems", []))
            managed_accounts = data.get("managedAccounts", data.get("ManagedAccounts", []))
        else:
            return {
                "requiredCoveragePercentage": False,
                "coveredSystems": 0,
                "totalSystems": 0,
                "coveragePercent": 0.0,
                "reason": "Expected merged dict with 'managedSystems' and 'managedAccounts' keys"
            }

        if not isinstance(managed_systems, list) or not isinstance(managed_accounts, list):
            return {
                "requiredCoveragePercentage": False,
                "coveredSystems": 0,
                "totalSystems": 0,
                "coveragePercent": 0.0,
                "reason": "managedSystems and managedAccounts must be lists"
            }

        total_systems = len(managed_systems)

        if total_systems == 0:
            return {
                "requiredCoveragePercentage": False,
                "coveredSystems": 0,
                "totalSystems": 0,
                "coveragePercent": 0.0,
                "reason": "No managed systems found"
            }

        # Build set of system IDs that have at least one account
        system_ids_with_accounts = set()
        for account in managed_accounts:
            system_id = account.get("ManagedSystemID")
            if system_id is not None:
                system_ids_with_accounts.add(system_id)

        # Count how many systems have accounts
        covered = 0
        for system in managed_systems:
            system_id = system.get("ManagedSystemID")
            if system_id in system_ids_with_accounts:
                covered += 1

        coverage = (covered / total_systems) * 100
        result = coverage >= COVERAGE_THRESHOLD

        return {
            "requiredCoveragePercentage": result,
            "coveredSystems": covered,
            "totalSystems": total_systems,
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review BeyondTrust configuration for {criteriaKey}")

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
