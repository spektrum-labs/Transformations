"""
Transformation: confirmedLicensePurchased
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether a valid Duo license is active, confirmed by a successful account summary response.
API Method: getAccountSummary (via checkLicenseStatus)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        # A valid non-empty account summary response confirms an active licensed Duo account.
        # The summary endpoint is only accessible on licensed accounts via the Admin API.
        if not isinstance(data, dict) or len(data) == 0:
            return {"confirmedLicensePurchased": False, "error": "No account summary data returned"}

        user_count = data.get("user_count", 0)
        admin_count = data.get("admin_count", 0)
        integration_count = data.get("integration_count", 0)
        telephony_credits = data.get("telephony_credits_remaining", None)

        # A valid response with recognisable summary fields confirms a licensed account.
        has_expected_fields = ("user_count" in data or "admin_count" in data or "integration_count" in data)
        license_purchased = has_expected_fields

        return {
            "confirmedLicensePurchased": license_purchased,
            "userCount": user_count,
            "adminCount": admin_count,
            "integrationCount": integration_count,
            "telephonyCreditsRemaining": telephony_credits
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

        user_count = eval_result.get("userCount", 0)
        admin_count = eval_result.get("adminCount", 0)
        integration_count = eval_result.get("integrationCount", 0)

        if result_value:
            pass_reasons.append("Duo account summary returned successfully, confirming an active license")
            pass_reasons.append("Registered users: " + str(user_count) + ", Admins: " + str(admin_count) + ", Integrations: " + str(integration_count))
        else:
            fail_reasons.append("Duo account summary did not return expected license fields")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that a valid Duo license is active and the Admin API credentials have 'Grant read information' permission")

        if eval_result.get("telephonyCreditsRemaining") is not None:
            additional_findings.append("Telephony credits remaining: " + str(eval_result["telephonyCreditsRemaining"]))

        return create_response(
            result={criteriaKey: result_value, "userCount": user_count, "adminCount": admin_count, "integrationCount": integration_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"userCount": user_count, "adminCount": admin_count, "integrationCount": integration_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
