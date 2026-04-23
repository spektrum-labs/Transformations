"""
Transformation: confirmedLicensePurchased
Vendor: SentinelOne  |  Category: epp
Evaluates: Ensure that a valid SentinelOne license is active and purchased for the account
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "SentinelOne", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        accounts = []
        if isinstance(data, list):
            accounts = data
        elif isinstance(data, dict):
            method_data = data.get("checkLicenseStatus", None)
            if isinstance(method_data, dict):
                val = method_data.get("data", [])
                if isinstance(val, list):
                    accounts = val
            if not accounts:
                val = data.get("data", [])
                if isinstance(val, list):
                    accounts = val
                elif isinstance(val, dict):
                    accounts = [val]

        if not accounts:
            return {"confirmedLicensePurchased": None, "error": "required fields missing from API response: data (accounts list from /accounts endpoint)"}

        active_count = 0
        paid_count = 0
        total_count = 0

        for account in accounts:
            if not isinstance(account, dict):
                continue
            total_count = total_count + 1
            state = account.get("state", "")
            account_type = account.get("accountType", "")
            active_licenses = account.get("activeLicenses", 0)

            state_str = state.lower() if isinstance(state, str) else ""
            type_str = account_type.lower() if isinstance(account_type, str) else ""

            if state_str == "active":
                active_count = active_count + 1

            is_trial = type_str in ("trial", "free", "")
            has_active_licenses = isinstance(active_licenses, (int, float)) and active_licenses > 0

            if not is_trial:
                paid_count = paid_count + 1
            elif has_active_licenses and state_str == "active":
                paid_count = paid_count + 1

        if total_count == 0:
            return {"confirmedLicensePurchased": None, "error": "required fields missing from API response: accounts data from /accounts endpoint"}

        license_purchased = active_count > 0 and paid_count > 0
        return {
            "confirmedLicensePurchased": license_purchased,
            "activeAccountCount": active_count,
            "paidAccountCount": paid_count,
            "totalAccountCount": total_count
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
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, None)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value is True:
            pass_reasons.append(criteriaKey + " check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be determined - insufficient data in API response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the integration is connected to the correct SentinelOne /accounts endpoint.")
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that a valid paid SentinelOne license is active. Navigate to Settings > License in the management console.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
