"""\nTransformation: confirmedLicensePurchased\nVendor: Critical Start  |  Category: insurability\nEvaluates: Verifies that an active Critical Start MDR subscription and license is present\nfor the account. Checks that subscriptionActive is true and subscriptionStatus indicates\nan active or enabled state.\n"""
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
                "vendor": "Critical Start",
                "category": "insurability"
            }
        }
    }


ACTIVE_STATUSES = ["active", "enabled", "current", "in_service", "in-service"]


def normalize_status(raw_status):
    if not raw_status:
        return ""
    return raw_status.lower().strip()


def evaluate(data):
    """
    Core evaluation logic for confirmedLicensePurchased.

    The merged workflow result contains fields from both getAccountInfo and
    getSubscriptionStatus. We look for:
      - subscriptionActive (bool): must be True
      - subscriptionStatus (str): must be one of the known active state strings

    Additional metadata fields (productName, licenseType, startDate, endDate, seats)
    are surfaced as findings but do not affect the pass/fail decision.
    """
    try:
        subscription_active = data.get("subscriptionActive", False)
        subscription_status = data.get("subscriptionStatus", "")
        product_name = data.get("productName", "")
        license_type = data.get("licenseType", "")
        start_date = data.get("startDate", "")
        end_date = data.get("endDate", "")
        seats = data.get("seats", 0)
        account_name = data.get("accountName", "")

        # Coerce subscriptionActive to bool in case it arrives as a string
        if isinstance(subscription_active, str):
            subscription_active = subscription_active.lower() in ("true", "1", "yes")

        normalized = normalize_status(subscription_status)
        status_is_active = normalized in ACTIVE_STATUSES

        confirmed = bool(subscription_active) and status_is_active

        return {
            "confirmedLicensePurchased": confirmed,
            "subscriptionActive": subscription_active,
            "subscriptionStatus": subscription_status,
            "productName": product_name,
            "licenseType": license_type,
            "startDate": start_date,
            "endDate": end_date,
            "seats": seats,
            "accountName": account_name
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteria_key = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)

        extra_fields = {
            k: v for k, v in eval_result.items()
            if k != criteria_key and k != "error"
        }

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        subscription_active = eval_result.get("subscriptionActive", False)
        subscription_status = eval_result.get("subscriptionStatus", "")
        product_name = eval_result.get("productName", "")
        license_type = eval_result.get("licenseType", "")
        start_date = eval_result.get("startDate", "")
        end_date = eval_result.get("endDate", "")
        seats = eval_result.get("seats", 0)
        account_name = eval_result.get("accountName", "")

        if product_name:
            additional_findings.append("Product: " + product_name)
        if license_type:
            additional_findings.append("License type: " + license_type)
        if start_date:
            additional_findings.append("Subscription start date: " + str(start_date))
        if end_date:
            additional_findings.append("Subscription end date: " + str(end_date))
        if seats:
            additional_findings.append("Licensed seats: " + str(seats))
        if account_name:
            additional_findings.append("Account name: " + account_name)

        if result_value:
            pass_reasons.append(
                "Critical Start MDR license is confirmed active (subscriptionActive=True, "
                "subscriptionStatus='" + subscription_status + "')"
            )
        else:
            if not subscription_active:
                fail_reasons.append(
                    "subscriptionActive is not True (value: " + str(subscription_active) + ")"
                )
            normalized = normalize_status(subscription_status)
            if normalized not in ACTIVE_STATUSES:
                fail_reasons.append(
                    "subscriptionStatus '" + subscription_status + "' does not indicate an "
                    "active state. Expected one of: " + ", ".join(ACTIVE_STATUSES)
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Verify that a valid Critical Start MDR subscription is active in the CORR "
                "portal (portal.criticalstart.io). Ensure the license has not expired and "
                "the subscription status is set to an active state."
            )

        input_summary = {
            "subscriptionActive": subscription_active,
            "subscriptionStatus": subscription_status,
            "productName": product_name,
            "licenseType": license_type,
            "seats": seats
        }

        return create_response(
            result={criteria_key: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
