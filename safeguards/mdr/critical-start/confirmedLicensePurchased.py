"""\nTransformation: confirmedLicensePurchased\nVendor: Critical Start  |  Category: mdr\nEvaluates: Checks if the Critical Start MDR subscription is active by verifying\nthe account subscription status field. Returns true if subscriptionStatus is\n'active' or an equivalent non-null, non-expired value.\n"""
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
                "category": "mdr"
            }
        }
    }


def parse_date(date_str):
    """Parse an ISO date string (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ) into a date tuple (year, month, day)."""
    if not date_str:
        return None
    cleaned = date_str.strip()
    # Handle datetime format with T separator
    if "T" in cleaned:
        cleaned = cleaned.split("T")[0]
    # Remove any trailing Z or timezone offset
    if "Z" in cleaned:
        cleaned = cleaned.replace("Z", "")
    parts = cleaned.split("-")
    if len(parts) < 3:
        return None
    year = int(parts[0])
    month = int(parts[1])
    day = int(parts[2][:2])
    return (year, month, day)


def date_tuple_to_comparable(tup):
    """Convert a (year, month, day) tuple to an integer for comparison."""
    if tup is None:
        return 0
    return tup[0] * 10000 + tup[1] * 100 + tup[2]


def evaluate(data):
    """
    Core evaluation logic for confirmedLicensePurchased.

    The merged getAssets payload (from getAccount + getIncidents) exposes:
      - subscriptionStatus  : str  (e.g. 'active', 'inactive', 'expired')
      - subscriptionPlan    : str  (plan name)
      - subscriptionStart   : str  (ISO date)
      - subscriptionEnd     : str  (ISO date)
      - status              : str  (account-level status)
      - id                  : str/int
      - name                : str  (account name)

    The criterion passes when subscriptionStatus is 'active' (case-insensitive)
    AND (if subscriptionEnd is present) the end date has not passed.
    """
    try:
        subscription_status = data.get("subscriptionStatus", None)
        subscription_plan = data.get("subscriptionPlan", None)
        subscription_start = data.get("subscriptionStart", None)
        subscription_end = data.get("subscriptionEnd", None)
        account_status = data.get("status", None)
        account_name = data.get("name", None)
        account_id = data.get("id", None)

        # Normalise status string
        status_str = ""
        if subscription_status is not None:
            status_str = str(subscription_status).strip().lower()

        # Primary check: subscriptionStatus must be 'active'
        status_is_active = status_str == "active"

        # Secondary check: if an end date exists, ensure it has not expired
        end_date_expired = False
        end_date_str = ""
        if subscription_end:
            end_tup = parse_date(str(subscription_end))
            if end_tup is not None:
                end_date_str = str(subscription_end)
                now = datetime.utcnow()
                now_comparable = now.year * 10000 + now.month * 100 + now.day
                end_comparable = date_tuple_to_comparable(end_tup)
                if end_comparable < now_comparable:
                    end_date_expired = True

        license_purchased = status_is_active and not end_date_expired

        return {
            "confirmedLicensePurchased": license_purchased,
            "subscriptionStatus": subscription_status,
            "subscriptionPlan": subscription_plan,
            "subscriptionStart": subscription_start,
            "subscriptionEnd": subscription_end,
            "endDateExpired": end_date_expired,
            "accountStatus": account_status,
            "accountName": account_name,
            "accountId": account_id
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

        subscription_status = eval_result.get("subscriptionStatus")
        subscription_plan = eval_result.get("subscriptionPlan")
        subscription_end = eval_result.get("subscriptionEnd")
        end_date_expired = eval_result.get("endDateExpired", False)
        account_name = eval_result.get("accountName")

        if result_value:
            pass_reasons.append(
                "Critical Start MDR subscription is active and has not expired"
            )
            if subscription_plan:
                pass_reasons.append("Subscription plan: " + str(subscription_plan))
            if subscription_end:
                pass_reasons.append("Subscription valid through: " + str(subscription_end))
            if account_name:
                pass_reasons.append("Account: " + str(account_name))
        else:
            if subscription_status is None or str(subscription_status).strip() == "":
                fail_reasons.append(
                    "Subscription status could not be determined — field is null or missing"
                )
            elif str(subscription_status).strip().lower() != "active":
                fail_reasons.append(
                    "Subscription status is not active (current value: " + str(subscription_status) + ")"
                )
            if end_date_expired:
                fail_reasons.append(
                    "Subscription end date has passed: " + str(subscription_end)
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

            recommendations.append(
                "Verify that a valid Critical Start MDR license has been purchased and that "
                "the subscription status in the CORR portal is set to 'active'."
            )
            recommendations.append(
                "If the subscription has expired, contact Critical Start support to renew "
                "the MDR service agreement."
            )

        if subscription_plan:
            additional_findings.append("Active plan: " + str(subscription_plan))

        return create_response(
            result={criteria_key: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "subscriptionStatus": subscription_status,
                "subscriptionPlan": subscription_plan,
                "subscriptionEnd": subscription_end,
                "accountName": account_name
            }
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
