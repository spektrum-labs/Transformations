"""
Transformation: isPasswordRotationOnReleaseEnabled
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether at least 50% of managed accounts have
ChangePasswordAfterAnyReleaseFlag set to true, confirming credential rotation
is enforced after checkout.
"""
import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isPasswordRotationOnReleaseEnabled',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

ROTATION_THRESHOLD = 50


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPasswordRotationOnReleaseEnabled", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """True if >= 50% of managed accounts have ChangePasswordAfterAnyReleaseFlag=true."""
    try:
        if isinstance(data, list):
            accounts = data
        elif isinstance(data, dict):
            accounts = data.get("ManagedAccounts", data.get("items", data.get("results", [])))
            if not isinstance(accounts, list):
                accounts = []
        else:
            return {"isPasswordRotationOnReleaseEnabled": None,
                    "error": "required fields missing from API response: ChangePasswordAfterAnyReleaseFlag"}

        total = len(accounts)
        if total == 0:
            return {"isPasswordRotationOnReleaseEnabled": False, "rotationCount": 0,
                    "totalAccounts": 0, "rotationPercent": 0,
                    "reason": "No managed accounts found"}

        rotation_count = 0
        for account in accounts:
            if not isinstance(account, dict):
                continue
            flag = account.get("ChangePasswordAfterAnyReleaseFlag", False)
            if isinstance(flag, str):
                flag = flag.lower() in ("true", "yes", "1")
            else:
                flag = bool(flag)
            if flag:
                rotation_count = rotation_count + 1

        rotation_pct = round((rotation_count / total) * 100)
        result = rotation_pct >= ROTATION_THRESHOLD
        return {"isPasswordRotationOnReleaseEnabled": result, "rotationCount": rotation_count,
                "totalAccounts": total, "rotationPercent": rotation_pct}
    except Exception as e:
        return {"isPasswordRotationOnReleaseEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPasswordRotationOnReleaseEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable ChangePasswordAfterAnyReleaseFlag on managed accounts in BeyondTrust Password Safe to reach " + str(ROTATION_THRESHOLD) + "% coverage.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
