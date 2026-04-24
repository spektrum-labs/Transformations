"""
Transformation: confirmLicensePurchased
Vendor: Crowdstrike  |  Category: epp
Evaluates: Confirm that the CrowdStrike Falcon EPP license is active and in use by verifying
that at least one managed device is enrolled in the platform. A successful API response with
a non-empty resources array confirms the license is purchased and active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmLicensePurchased", "vendor": "Crowdstrike", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        resources = None

        # Try method-keyed merged format first (workflow merges multiple method results)
        if isinstance(data, dict):
            qd = data.get("queryDevices", None)
            if isinstance(qd, dict):
                resources = qd.get("resources", None)

        # Fall back to flat top-level format
        if resources is None and isinstance(data, dict):
            resources = data.get("resources", None)

        if resources is None:
            return {
                "confirmLicensePurchased": None,
                "error": "required fields missing from API response: resources"
            }

        if not isinstance(resources, list):
            return {
                "confirmLicensePurchased": None,
                "error": "resources field is not a list"
            }

        device_count = len(resources)
        is_licensed = device_count > 0

        return {
            "confirmLicensePurchased": is_licensed,
            "enrolledDeviceCount": device_count
        }
    except Exception as e:
        return {"confirmLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value is True:
            pass_reasons.append(criteriaKey + " check passed")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields.get(k)))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be evaluated: insufficient data in API response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the queryDevices API endpoint returns a non-empty resources array")
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure at least one device is enrolled in CrowdStrike Falcon to confirm an active EPP license")
            for k in extra_fields:
                fail_reasons.append(k + ": " + str(extra_fields.get(k)))

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
            fail_reasons=["Transformation error: " + str(e)]
        )
