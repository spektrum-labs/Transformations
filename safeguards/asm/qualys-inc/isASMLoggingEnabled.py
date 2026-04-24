"""
Transformation: isASMLoggingEnabled
Vendor: Qualys, Inc.  |  Category: asm
Evaluates: Ensures a valid API response is returned, confirming that the CSAM
subscription is active and API-level activity logging is operational within
the Qualys platform.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isASMLoggingEnabled", "vendor": "Qualys, Inc.", "category": "asm"}
        }
    }


def evaluate(data):
    try:
        response_code = ""
        asset_count = 0
        response_message = ""

        if isinstance(data, dict):
            response_code = data.get("responseCode", "")
            asset_count = data.get("count", 0)
            response_message = data.get("responseMessage", "")

        logging_enabled = (str(response_code).upper() == "SUCCESS")

        return {
            "isASMLoggingEnabled": logging_enabled,
            "responseCode": response_code,
            "responseMessage": response_message,
            "assetCount": asset_count
        }
    except Exception as e:
        return {"isASMLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isASMLoggingEnabled"
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
        response_code = eval_result.get("responseCode", "")
        response_message = eval_result.get("responseMessage", "")
        asset_count = eval_result.get("assetCount", 0)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Qualys CSAM subscription is active and API-level activity logging is operational")
            pass_reasons.append("CSAM count endpoint responded successfully with responseCode: " + str(response_code))
            if asset_count:
                pass_reasons.append("Logged asset count returned by CSAM API: " + str(asset_count))
        else:
            fail_reasons.append("Qualys ASM logging could not be confirmed — CSAM API did not return a SUCCESS responseCode")
            if response_code:
                fail_reasons.append("Received responseCode: " + str(response_code))
            if response_message:
                fail_reasons.append("API message: " + str(response_message))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the Qualys CSAM module is active and the API endpoint is reachable from your configured gateway URL")
            recommendations.append("Confirm the Qualys user account has the required API access permissions to invoke CSAM endpoints")
            recommendations.append("Review Qualys platform audit logs to verify API-level activity tracking is configured")

        return create_response(
            result={
                criteriaKey: result_value,
                "responseCode": response_code,
                "responseMessage": response_message,
                "assetCount": asset_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "responseCode": response_code,
                "assetCount": asset_count,
                criteriaKey: result_value
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
