"""
Transformation: confirmedLicensePurchased
Vendor: Qualys, Inc.  |  Category: asm
Evaluates: Whether the Qualys CSAM/EASM license is active and purchased, determined by
a successful response from the Qualys asset count endpoint (count >= 0 and valid responseCode).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Qualys, Inc.", "category": "asm"}
        }
    }


def evaluate(data):
    """
    Checks the Qualys CSAM asset count API response.
    returnSpec: { count: int, responseCode: str }
    A valid response (responseCode present and count is a non-negative integer) confirms
    the CSAM/EASM license is active.
    """
    try:
        if not isinstance(data, dict):
            return {"confirmedLicensePurchased": False, "error": "Unexpected response format: data is not a dict"}

        response_code = data.get("responseCode", "")
        count = data.get("count", None)

        response_code_str = str(response_code) if response_code is not None else ""
        code_ok = response_code_str == "200" or response_code_str == ""

        count_ok = False
        asset_count = 0
        if count is not None:
            try:
                asset_count = int(count)
                count_ok = asset_count >= 0
            except Exception:
                count_ok = False

        license_purchased = code_ok and count_ok

        return {
            "confirmedLicensePurchased": license_purchased,
            "responseCode": response_code_str,
            "assetCount": asset_count
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Qualys CSAM asset count endpoint returned a valid response")
            pass_reasons.append("CSAM/EASM license is active and confirmed as purchased")
            rc = extra_fields.get("responseCode", "")
            if rc:
                pass_reasons.append("Response code: " + rc)
            pass_reasons.append("Asset count returned: " + str(extra_fields.get("assetCount", 0)))
        else:
            fail_reasons.append("Qualys CSAM asset count endpoint did not return a valid response")
            fail_reasons.append("CSAM/EASM license may not be active or purchased")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Verify that the CSAM/EASM license is active on your Qualys subscription")
            recommendations.append("Contact your Qualys account manager to confirm license entitlements")

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
