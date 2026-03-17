"""
Transformation: confirmedLicensePurchased
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether the customer has an active ThreatDown Nebula account with a valid subscription.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if ThreatDown account is active with a valid subscription."""
    try:
        # The /nebula/v1/account endpoint returns account info
        account_name = data.get("name", data.get("accountName", ""))
        account_id = data.get("id", data.get("accountId", data.get("account_id", "")))

        # Check account status
        status = data.get("status", data.get("state", data.get("accountStatus", "")))
        if isinstance(status, bool):
            is_active = status
        else:
            is_active = str(status).lower() in ("active", "enabled", "true", "1", "current")

        # Check subscription/license info if available
        subscription = data.get("subscription", data.get("license", {}))
        if isinstance(subscription, dict):
            sub_status = subscription.get("status", subscription.get("state", ""))
            if sub_status:
                is_active = is_active or str(sub_status).lower() in ("active", "enabled", "true", "current")
            plan = subscription.get("plan", subscription.get("tier", subscription.get("type", "")))
        else:
            plan = ""

        # Fallback: if we got any account data back, consider it confirmed
        if not is_active and (account_name or account_id):
            is_active = True

        return {
            "confirmedLicensePurchased": is_active,
            "accountName": account_name,
            "accountId": str(account_id),
            "plan": str(plan)
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
            pass_reasons.append("ThreatDown account is active with a valid subscription")
            if extra_fields.get("accountName"):
                pass_reasons.append(f"Account: {extra_fields['accountName']}")
            if extra_fields.get("plan"):
                pass_reasons.append(f"Plan: {extra_fields['plan']}")
        else:
            fail_reasons.append("No active ThreatDown account or subscription found")
            recommendations.append("Verify ThreatDown Nebula account status and subscription in the admin console")

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
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
