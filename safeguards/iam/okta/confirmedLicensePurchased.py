"""
Transformation: confirmedLicensePurchased
Vendor: Okta  |  Category: iam
Evaluates: Fetches org details from /api/v1/org and confirms the organization record is
ACTIVE, verifying that a valid Okta license has been purchased and is in use.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Okta", "category": "iam"}
        }
    }


def get_org_data(data):
    """Extract the org info dict regardless of input shape."""
    if isinstance(data, dict):
        if "getOrgInfo" in data and isinstance(data["getOrgInfo"], dict):
            return data["getOrgInfo"]
        if "id" in data or "status" in data or "companyName" in data:
            return data
        for key in ["orgInfo", "org", "organization"]:
            if key in data and isinstance(data[key], dict):
                return data[key]
    return {}


def evaluate(data):
    """Confirm the Okta org is ACTIVE, indicating a valid license is in use."""
    try:
        org = get_org_data(data)
        status = org.get("status", "")
        org_id = org.get("id", "")
        company_name = org.get("companyName", "")
        subdomain = org.get("subdomain", "")
        website = org.get("website", "")
        is_active = status == "ACTIVE"
        has_id = len(org_id) > 0
        is_confirmed = is_active and has_id

        return {
            "confirmedLicensePurchased": is_confirmed,
            "orgStatus": status,
            "orgId": org_id,
            "companyName": company_name,
            "subdomain": subdomain,
            "website": website
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
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        company = extra_fields.get("companyName", "")
        org_status = extra_fields.get("orgStatus", "")
        if result_value:
            pass_reasons.append("Okta organization is ACTIVE, confirming a valid license is in use.")
            if company:
                pass_reasons.append("Organization: " + company)
            if extra_fields.get("subdomain", ""):
                pass_reasons.append("Subdomain: " + extra_fields["subdomain"])
        else:
            fail_reasons.append("Okta organization is not confirmed as ACTIVE (status: " + org_status + ").")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            if not extra_fields.get("orgId", ""):
                fail_reasons.append("No organization ID found in the API response.")
            recommendations.append("Verify that a valid Okta license is purchased and that the org status is ACTIVE.")
        if org_status:
            additional_findings.append("Org status returned by API: " + org_status)
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "orgStatus": org_status})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
