"""
Transformation: confirmedLicensePurchased
Vendor: Crowdstrike  |  Category: epp
Evaluates: Whether a valid CrowdStrike Falcon Prevent (or equivalent) license is active
           by confirming the prevention policies API returns at least one policy resource,
           indicating the tenant is provisioned and licensed.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def get_prevention_policies(data):
    """Extract prevention policies list from merged or direct API response."""
    if isinstance(data, dict):
        method_data = data.get("getPreventionPolicies", None)
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
    """
    Check whether the prevention policies API returned at least one resource,
    confirming the Falcon Prevent license is active and the tenant is provisioned.
    """
    try:
        policies = get_prevention_policies(data)
        total_policies = len(policies)
        license_confirmed = total_policies > 0
        policy_names = [p.get("name", "unnamed") for p in policies]
        platform_names = []
        for p in policies:
            pn = p.get("platform_name", "")
            if pn and pn not in platform_names:
                platform_names.append(pn)
        return {
            "confirmedLicensePurchased": license_confirmed,
            "totalPolicies": total_policies,
            "policyNames": policy_names,
            "platformNames": platform_names
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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
            pass_reasons.append("CrowdStrike prevention policies API returned " + str(eval_result.get("totalPolicies", 0)) + " policy resource(s), confirming a valid Falcon Prevent license is active and the tenant is provisioned.")
            platforms = eval_result.get("platformNames", [])
            if platforms:
                pass_reasons.append("Policies found for platform(s): " + ", ".join(platforms))
        else:
            fail_reasons.append("No prevention policy resources were returned by the API — license may be inactive or the tenant is not fully provisioned.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that a CrowdStrike Falcon Prevent or equivalent license has been purchased and activated for this tenant.")
            recommendations.append("Ensure the API client has Prevention Policies Read scope enabled.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalPolicies": eval_result.get("totalPolicies", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
