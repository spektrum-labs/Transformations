"""
Transformation: confirmedLicensePurchased
Vendor: MDR (mdr)  |  Category: MDR
Evaluates: Whether a valid MDR licence has been purchased and is active.
           Reads the 'licensePurchased' field from the getMDRStatus response.
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
                "vendor": "mdr",
                "category": "MDR"
            }
        }
    }


def evaluate(data):
    try:
        license_purchased = data.get("licensePurchased", False)
        service_active = data.get("serviceActive", False)
        status = data.get("status", "unknown")

        is_licensed = bool(license_purchased)

        return {
            "confirmedLicensePurchased": is_licensed,
            "licensePurchasedFlag": is_licensed,
            "serviceActive": bool(service_active),
            "serviceStatus": str(status)
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
        additional_findings = []

        if result_value:
            pass_reasons.append("A valid MDR licence is confirmed purchased and active")
            pass_reasons.append("licensePurchasedFlag: " + str(extra_fields.get("licensePurchasedFlag", False)))
        else:
            fail_reasons.append("No active MDR licence is confirmed in the vendor response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Purchase a valid MDR licence through your vendor portal and ensure it is "
                "activated for your organisation before proceeding"
            )

        additional_findings.append("serviceStatus: " + str(extra_fields.get("serviceStatus", "unknown")))
        additional_findings.append("serviceActive: " + str(extra_fields.get("serviceActive", False)))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "licensePurchasedFlag": extra_fields.get("licensePurchasedFlag"),
                "serviceActive": extra_fields.get("serviceActive"),
                "serviceStatus": extra_fields.get("serviceStatus")
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
