"""
Transformation: confirmLicensePurchased
Vendor: Halcyon  |  Category: claims-defense
Evaluates: Confirms a valid Halcyon license has been purchased and is currently active by
inspecting the account subscription status returned from the /v1/account endpoint. Returns
true if the licensePurchased field is present and truthy.
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
                "transformationId": "confirmLicensePurchased",
                "vendor": "Halcyon",
                "category": "claims-defense"
            }
        }
    }


def extract_subscription_details(subscription):
    details = {}
    if not isinstance(subscription, dict):
        return details
    for field in ["plan", "tier", "type", "status", "expiryDate", "expiry_date", "expiresAt", "expires_at", "seats", "licenseCount"]:
        val = subscription.get(field)
        if val is not None:
            details[field] = val
    return details


def evaluate(data):
    try:
        license_purchased = data.get("licensePurchased", None)

        if license_purchased is None:
            account_data = data.get("data", {})
            if isinstance(account_data, dict):
                license_purchased = account_data.get("licensePurchased", None)

        if license_purchased is None:
            subscription = data.get("subscription", {})
            if isinstance(subscription, dict):
                sub_status = subscription.get("status", "")
                if sub_status:
                    sub_status_lower = str(sub_status).lower()
                    if "active" in sub_status_lower or "valid" in sub_status_lower:
                        license_purchased = True
                    elif "inactive" in sub_status_lower or "expired" in sub_status_lower or "cancelled" in sub_status_lower:
                        license_purchased = False

        license_active = bool(license_purchased) if license_purchased is not None else False

        subscription = data.get("subscription", {})
        subscription_details = extract_subscription_details(subscription)

        sso_enabled = data.get("ssoEnabled", False)
        idp_configured = data.get("idpConfigured", False)

        return {
            "confirmLicensePurchased": license_active,
            "licensePurchased": license_active,
            "subscriptionDetails": subscription_details,
            "ssoEnabled": bool(sso_enabled),
            "idpConfigured": bool(idp_configured)
        }

    except Exception as e:
        return {"confirmLicensePurchased": False, "evaluationNote": str(e)}


def transform(input):
    criteriaKey = "confirmLicensePurchased"
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "evaluationNote":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("A valid Halcyon license has been confirmed as purchased and active.")
            sub_details = eval_result.get("subscriptionDetails", {})
            if sub_details:
                for field in sub_details:
                    additional_findings.append("Subscription " + field + ": " + str(sub_details[field]))
        else:
            note = eval_result.get("evaluationNote", "")
            if note:
                fail_reasons.append(note)
            else:
                fail_reasons.append("The licensePurchased field is absent or false in the Halcyon account response.")
            recommendations.append(
                "Verify that a valid Halcyon license has been purchased and that the account is in an active subscription state."
            )
            recommendations.append(
                "Contact Halcyon support to confirm licensing status if the account appears active in the console but this check fails."
            )

        final_result = {criteriaKey: result_value}
        for k in extra_fields:
            final_result[k] = extra_fields[k]

        input_summary = {
            "licensePurchased": eval_result.get("licensePurchased", False),
            "ssoEnabled": eval_result.get("ssoEnabled", False),
            "idpConfigured": eval_result.get("idpConfigured", False)
        }

        return create_response(
            result=final_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
