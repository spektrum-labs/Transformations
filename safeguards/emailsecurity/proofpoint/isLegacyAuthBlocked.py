"""
Transformation: isLegacyAuthBlocked
Vendor: Proofpoint  |  Category: emailsecurity
Evaluates: Check the Azure permissions response to determine whether legacy authentication
protocols are blocked via the Proofpoint Essentials Azure integration settings (getAzurePermissions).
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
                "transformationId": "isLegacyAuthBlocked",
                "vendor": "Proofpoint",
                "category": "emailsecurity"
            }
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isLegacyAuthBlocked": False, "error": "Unexpected data format"}

        permissions = data.get("permissions", {})
        if not isinstance(permissions, dict):
            permissions = {}

        legacy_auth_blocked = data.get(
            "legacy_auth_blocked",
            permissions.get("legacy_auth_blocked", None)
        )
        block_legacy = data.get(
            "block_legacy_authentication",
            permissions.get("block_legacy_authentication", None)
        )
        conditional_access = data.get(
            "conditional_access_enabled",
            permissions.get("conditional_access_enabled", None)
        )
        modern_auth_only = data.get(
            "modern_auth_only",
            permissions.get("modern_auth_only", None)
        )

        is_blocked = (
            bool(legacy_auth_blocked) or
            bool(block_legacy) or
            bool(modern_auth_only)
        )

        return {
            "isLegacyAuthBlocked": is_blocked,
            "legacyAuthBlocked": legacy_auth_blocked,
            "blockLegacyAuthentication": block_legacy,
            "conditionalAccessEnabled": conditional_access
        }
    except Exception as e:
        return {"isLegacyAuthBlocked": False, "error": str(e)}


def transform(input):
    criteriaKey = "isLegacyAuthBlocked"
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
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Legacy authentication protocols are blocked via Azure integration settings")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("Legacy authentication protocols are not confirmed as blocked")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Block legacy authentication in Azure AD / Proofpoint Essentials Azure integration to prevent credential attacks"
            )
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        input_summary = {criteriaKey: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
