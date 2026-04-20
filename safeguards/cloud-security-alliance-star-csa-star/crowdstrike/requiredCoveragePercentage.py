"""
Transformation: requiredCoveragePercentage
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: The percentage of managed endpoints with an active CrowdStrike sensor
           (status: 'normal'). Passes when coverage meets or exceeds 80%.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Crowdstrike", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        total_devices = len(resources)

        if total_devices == 0:
            return {
                "requiredCoveragePercentage": 0,
                "totalDevices": 0,
                "activeDevices": 0,
                "inactiveDevices": 0,
                "coverageMeetsThreshold": False,
                "coverageThreshold": 80,
                "error": "No device resources found in API response"
            }

        active_devices = [d for d in resources if d.get("status", "") == "normal"]
        active_count = len(active_devices)
        inactive_count = total_devices - active_count

        coverage_percentage = (active_count * 100) / total_devices
        coverage_rounded = int(coverage_percentage * 100) / 100
        threshold = 80
        meets_threshold = coverage_percentage >= threshold

        status_breakdown = {}
        for d in resources:
            s = d.get("status", "unknown")
            if s in status_breakdown:
                status_breakdown[s] = status_breakdown[s] + 1
            else:
                status_breakdown[s] = 1

        return {
            "requiredCoveragePercentage": coverage_rounded,
            "totalDevices": total_devices,
            "activeDevices": active_count,
            "inactiveDevices": inactive_count,
            "coverageMeetsThreshold": meets_threshold,
            "coverageThreshold": threshold,
            "statusBreakdown": status_breakdown
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0, "coverageMeetsThreshold": False, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: 0, "coverageMeetsThreshold": False}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, 0)
        meets_threshold = eval_result.get("coverageMeetsThreshold", False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalDevices", 0)
        active = eval_result.get("activeDevices", 0)
        threshold = eval_result.get("coverageThreshold", 80)
        status_breakdown = eval_result.get("statusBreakdown", {})

        if meets_threshold:
            pass_reasons.append("EPP agent coverage meets or exceeds the required " + str(threshold) + "% threshold")
            pass_reasons.append("Coverage: " + str(result_value) + "% (" + str(active) + " of " + str(total) + " devices with active sensor)")
        else:
            fail_reasons.append("EPP agent coverage is below the required " + str(threshold) + "% threshold")
            fail_reasons.append("Current coverage: " + str(result_value) + "% (" + str(active) + " of " + str(total) + " devices with active sensor)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Investigate and remediate devices not reporting as 'normal' status")
            recommendations.append("Ensure the CrowdStrike Falcon sensor is deployed and running on all managed endpoints")
            recommendations.append("Review devices in 'reduced_functionality_mode' or containment states")

        if status_breakdown:
            for s in status_breakdown:
                additional_findings.append("Status '" + s + "': " + str(status_breakdown[s]) + " device(s)")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalDevices": total, "activeDevices": active, "coveragePercentage": result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: 0, "coverageMeetsThreshold": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
