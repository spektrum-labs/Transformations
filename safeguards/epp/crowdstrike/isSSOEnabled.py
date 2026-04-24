"""
Transformation: isSSOEnabled
Vendor: Crowdstrike  |  Category: epp
Evaluates: Whether user records are present in the CrowdStrike tenant, used as a proxy
           for identity and access management (SSO/IAM) being configured. Returns true
           if at least one user record is returned by the user management API.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def get_users(data):
    """Extract user records from merged or direct API response."""
    if isinstance(data, dict):
        method_data = data.get("getUsers", None)
        if method_data is not None:
            if isinstance(method_data, dict):
                return method_data.get("data", [])
            if isinstance(method_data, list):
                return method_data
        direct = data.get("data", None)
        if isinstance(direct, list):
            return direct
        resources = data.get("resources", None)
        if isinstance(resources, list):
            return resources
    if isinstance(data, list):
        return data
    return []


def evaluate(data):
    """Check if user records are present as a proxy for SSO/IAM configuration."""
    try:
        users = get_users(data)
        total_users = len(users)
        is_sso_enabled = total_users > 0
        return {
            "isSSOEnabled": is_sso_enabled,
            "totalUsers": total_users
        }
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSSOEnabled"
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
        additional_findings.append("SSO is evaluated as a proxy: user records present in the CrowdStrike tenant indicate IAM/SSO provisioning. For a definitive SSO check, the SAML configuration endpoint (/settings/entities/saml-config/v1) would need to be queried.")
        if result_value:
            pass_reasons.append("User records are present in the CrowdStrike tenant (" + str(eval_result.get("totalUsers", 0)) + " user(s) found), confirming identity management is configured.")
        else:
            fail_reasons.append("No user records were returned by the user management API.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that the API client has User Management Read scope and that SSO/SAML is configured in the Falcon Console under Support > Identity Provider Settings.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalUsers": eval_result.get("totalUsers", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
