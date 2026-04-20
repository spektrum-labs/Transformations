"""
Transformation: confirmedLicensePurchased
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Confirm that a valid CrowdStrike Falcon license is active by verifying that the API
           responds successfully to /policy/combined/prevention/v1 and returns at least one
           prevention policy resource, which is only possible with an active subscription.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
                "vendor": "Crowdstrike",
                "category": "cloud-security-alliance-star-csa-star"
            }
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            resources = []
        total_policies = len(resources)
        license_confirmed = total_policies > 0
        policy_names = []
        for policy in resources:
            if isinstance(policy, dict):
                name = policy.get("name", "")
                if name:
                    policy_names.append(name)
        return {
            "confirmedLicensePurchased": license_confirmed,
            "totalPoliciesFound": total_policies,
            "policyNames": policy_names
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(
                "CrowdStrike Falcon license is active — prevention policy API returned "
                + str(eval_result.get("totalPoliciesFound", 0)) + " policy resource(s)"
            )
            policy_names = eval_result.get("policyNames", [])
            if policy_names:
                additional_findings.append("Prevention policies found: " + ", ".join(policy_names))
        else:
            fail_reasons.append(
                "No prevention policy resources returned from /policy/combined/prevention/v1 — "
                "a valid CrowdStrike Falcon license could not be confirmed"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Verify that a valid CrowdStrike Falcon license is active and that the API client "
                "has the Prevention Policies read scope enabled"
            )
        result_dict = {
            criteriaKey: result_value,
            "totalPoliciesFound": eval_result.get("totalPoliciesFound", 0)
        }
        policy_names = eval_result.get("policyNames", [])
        if policy_names:
            result_dict["policyNames"] = policy_names
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                criteriaKey: result_value,
                "totalPoliciesFound": eval_result.get("totalPoliciesFound", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
