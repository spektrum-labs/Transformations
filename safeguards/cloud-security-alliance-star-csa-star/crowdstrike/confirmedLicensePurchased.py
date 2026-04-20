"""
Transformation: confirmedLicensePurchased
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Whether the CrowdStrike Falcon license is active and devices are enrolled.
           A non-empty resources[] array from GET /devices/combined/devices/v1
           confirms that the license is valid and devices are managed under the account.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Crowdstrike", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        total_devices = len(resources)
        license_confirmed = total_devices > 0

        platform_counts = {}
        for d in resources:
            platform = d.get("platform_name", d.get("os_version", "unknown"))
            if platform in platform_counts:
                platform_counts[platform] = platform_counts[platform] + 1
            else:
                platform_counts[platform] = 1

        return {
            "confirmedLicensePurchased": license_confirmed,
            "totalEnrolledDevices": total_devices,
            "platformBreakdown": platform_counts
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "totalEnrolledDevices": 0, "error": str(e)}


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

        total = eval_result.get("totalEnrolledDevices", 0)
        platform_breakdown = eval_result.get("platformBreakdown", {})

        if result_value:
            pass_reasons.append("CrowdStrike Falcon license is confirmed active -- enrolled devices are present in the account")
            pass_reasons.append("Total enrolled devices: " + str(total))
            if platform_breakdown:
                for p in platform_breakdown:
                    additional_findings.append("Platform '" + p + "': " + str(platform_breakdown[p]) + " device(s)")
        else:
            fail_reasons.append("No enrolled devices found -- CrowdStrike Falcon license could not be confirmed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that a valid CrowdStrike Falcon license is active for this account")
            recommendations.append("Ensure at least one endpoint has the Falcon sensor deployed and enrolled")
            recommendations.append("Confirm API credentials have sufficient scope (hosts:read) to retrieve device inventory")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalEnrolledDevices": total}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
