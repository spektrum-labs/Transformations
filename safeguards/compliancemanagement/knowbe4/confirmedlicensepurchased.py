"""
Transformation: confirmedLicensePurchased
Vendor: KnowBe4  |  Category: Compliance Management
Evaluates: Whether KnowBe4 subscription is active and not expired
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "KnowBe4", "category": "Compliance Management"}
        }
    }


def evaluate(data):
    """Core evaluation logic. None (not measured) when the body is not an account at all."""
    if not isinstance(data, dict) or data.get("error") is True or "subscription_level" not in data:
        return {"confirmedLicensePurchased": None,
                "error": "The response is not a KnowBe4 account with a subscription level; nothing to measure."}
    try:
        from datetime import timezone
        sub_level = data.get('subscription_level')
        end_date = data.get('subscription_end_date', '')
        if not isinstance(sub_level, str) or not sub_level.strip():
            return {"confirmedLicensePurchased": None,
                    "error": "The KnowBe4 account has no readable subscription level; nothing to measure."}
        is_active = sub_level.strip().lower() != 'free'
        if end_date:
            expiry = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            if expiry.tzinfo is None:
                # /v1/account documents a date only ("2021-03-06"); naive vs aware comparison raised.
                expiry = expiry.replace(tzinfo=timezone.utc)
            is_active = is_active and expiry > datetime.now(timezone.utc)
        return {"confirmedLicensePurchased": is_active, "subscriptionLevel": sub_level}
    except Exception:
        return {"confirmedLicensePurchased": None,
                "error": "The subscription level or end date in the KnowBe4 account could not be read."}


def not_measured(reason, validation):
    """No verdict: None plus a data-collection error, shown as Not evaluated and never as a failed check."""
    return create_response(result={"confirmedLicensePurchased": None}, validation=validation,
                           fail_reasons=[reason], api_errors=[reason])


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_measured("Input validation failed: the response is not a KnowBe4 account.", validation)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey)
        if result_value is None:
            return not_measured(eval_result.get("error") or "The KnowBe4 account could not be read.", validation)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review KnowBe4 configuration for {criteriaKey}")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception:
        reason = "The KnowBe4 account response could not be read, so the subscription was not evaluated."
        return create_response(
            result={criteriaKey: None}, validation={"status": "error", "errors": [], "warnings": []},
            api_errors=[reason], transformation_errors=["The KnowBe4 account response could not be processed."],
            fail_reasons=[reason])
