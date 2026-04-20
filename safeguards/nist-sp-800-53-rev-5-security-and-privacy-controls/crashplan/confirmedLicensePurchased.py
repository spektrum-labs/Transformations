"""
Transformation: confirmedLicensePurchased
Vendor: CrashPlan  |  Category: nist-sp-800-53-rev-5-security-and-privacy-controls
Evaluates: Whether a valid CrashPlan license has been purchased and is in active use,
           determined by inspecting the GET /api/v1/Org response for a non-empty active
           organizations array.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for iteration in range(3):
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "CrashPlan",
                "category": "nist-sp-800-53-rev-5-security-and-privacy-controls"
            }
        }
    }


def evaluate(data):
    """
    Inspect the merged getOrg data.
    Passes when at least one active organization is present in the response,
    confirming a valid CrashPlan license is in use.
    Also reports org names and total count for audit purposes.
    """
    try:
        orgs = data.get("orgs", [])
        if not isinstance(orgs, list):
            orgs = []

        total_orgs = len(orgs)

        if total_orgs == 0:
            return {
                "confirmedLicensePurchased": False,
                "totalOrgs": 0,
                "activeOrgs": 0,
                "orgNames": [],
                "error": "No organizations found in the CrashPlan Org API — license may not be active"
            }

        active_orgs = 0
        org_names = []

        for org in orgs:
            is_active = org.get("active", False)
            if is_active:
                active_orgs = active_orgs + 1
                org_name = org.get("orgName", org.get("name", "Unknown"))
                org_names.append(org_name)

        is_licensed = active_orgs > 0

        return {
            "confirmedLicensePurchased": is_licensed,
            "totalOrgs": total_orgs,
            "activeOrgs": active_orgs,
            "orgNames": org_names
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteria_key = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalOrgs", 0)
        active = eval_result.get("activeOrgs", 0)
        org_names = eval_result.get("orgNames", [])

        if result_value:
            pass_reasons.append(
                "CrashPlan license is confirmed: " + str(active) +
                " active organization(s) found out of " + str(total) + " total"
            )
            if len(org_names) > 0:
                pass_reasons.append(
                    "Active organization(s): " + ", ".join(org_names)
                )
        else:
            fail_reasons.append(
                "No active CrashPlan organizations found — license purchase cannot be confirmed"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Verify that a CrashPlan license has been purchased and that the account is active"
            )
            recommendations.append(
                "Ensure the API credentials have read access to the Org resource in CrashPlan"
            )

        inactive_orgs = total - active
        if inactive_orgs > 0:
            additional_findings.append(
                str(inactive_orgs) + " organization(s) exist but are inactive"
            )

        result_dict = {criteria_key: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        input_summary = {criteria_key: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
