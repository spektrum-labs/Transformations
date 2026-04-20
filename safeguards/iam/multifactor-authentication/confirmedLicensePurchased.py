"""
Transformation: confirmedLicensePurchased
Vendor: Multifactor Authentication  |  Category: iam
Evaluates: Check the billing edition returned by the Duo API. A paid edition such as
           enterprise, business, advantage, premier, or essentials confirms that a valid
           Duo license has been purchased. Free or trial editions do not pass.
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
                "vendor": "Multifactor Authentication",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    try:
        paid_editions = ["enterprise", "business", "advantage", "premier", "essentials",
                         "federal", "government"]
        free_editions = ["free", "trial", "personal", "community"]

        edition = ""
        if "edition" in data:
            edition = str(data["edition"]).lower()
        elif "response" in data and isinstance(data.get("response"), dict):
            edition = str(data["response"].get("edition", "")).lower()
        elif "billing_edition" in data:
            edition = str(data["billing_edition"]).lower()

        is_paid = False
        for paid in paid_editions:
            if paid in edition:
                is_paid = True
                break

        is_free = False
        for free in free_editions:
            if free in edition:
                is_free = True
                break

        edition_detected = edition if edition else "unknown"

        return {
            "confirmedLicensePurchased": is_paid,
            "detectedEdition": edition_detected,
            "isPaidEdition": is_paid,
            "isFreeOrTrialEdition": is_free,
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
                fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        edition = eval_result.get("detectedEdition", "unknown")
        if result_value:
            pass_reasons.append("A valid paid Duo license has been confirmed")
            pass_reasons.append("Detected billing edition: " + edition)
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if edition == "unknown":
                fail_reasons.append("Unable to determine the Duo billing edition from the API response")
                recommendations.append("Verify that the API credential has 'Grant read information' permission to access billing data")
            elif eval_result.get("isFreeOrTrialEdition", False):
                fail_reasons.append("Detected edition '" + edition + "' is a free or trial edition; a paid license is required")
                recommendations.append("Purchase a Duo paid edition (e.g. Essentials, Advantage, Premier) to meet this requirement")
            else:
                fail_reasons.append("Detected edition '" + edition + "' is not recognized as a paid Duo edition")
                recommendations.append("Confirm the correct Duo billing edition is applied to the account")
        additional_findings.append("Duo billing edition detected: " + edition)
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"detectedEdition": edition, "isPaidEdition": result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
