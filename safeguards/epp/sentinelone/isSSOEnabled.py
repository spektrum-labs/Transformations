"""
Transformation: isSSOEnabled
Vendor: SentinelOne  |  Category: epp
Evaluates: Check if Single Sign-On (SSO/SAML) is enabled and configured for the SentinelOne management console
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "SentinelOne", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        sso_data = {}
        if isinstance(data, dict):
            method_data = data.get("getSSOSettings", None)
            if isinstance(method_data, dict):
                val = method_data.get("data", {})
                if isinstance(val, dict) and val:
                    sso_data = val
            if not sso_data:
                val = data.get("data", {})
                if isinstance(val, dict) and val:
                    sso_data = val
                elif isinstance(val, list) and len(val) > 0:
                    first = val[0]
                    if isinstance(first, dict):
                        sso_data = first
            if not sso_data:
                sso_check_fields = ["isSsoEnabled", "ssoEnabled", "samlEnabled", "enabled", "isEnabled", "entityId", "loginUrl"]
                found = False
                for field in sso_check_fields:
                    if field in data:
                        found = True
                        break
                if found:
                    sso_data = data

        if not sso_data:
            return {"isSSOEnabled": None, "error": "required fields missing from API response: SSO settings data from /sso endpoint (isSsoEnabled, ssoEnabled, samlEnabled, entityId, loginUrl)"}

        raw_enabled = sso_data.get("isSsoEnabled", None)
        if raw_enabled is None:
            raw_enabled = sso_data.get("ssoEnabled", None)
        if raw_enabled is None:
            raw_enabled = sso_data.get("samlEnabled", None)
        if raw_enabled is None:
            raw_enabled = sso_data.get("enabled", None)
        if raw_enabled is None:
            raw_enabled = sso_data.get("isEnabled", None)

        if raw_enabled is None:
            entity_id = sso_data.get("entityId", "")
            login_url = sso_data.get("loginUrl", "")
            certificate = sso_data.get("certificate", "")
            has_config = bool(entity_id) or bool(login_url) or bool(certificate)
            if has_config:
                return {"isSSOEnabled": True, "inferredFromSSOConfig": True}
            return {"isSSOEnabled": None, "error": "required fields missing from API response: isSsoEnabled, ssoEnabled, samlEnabled, entityId, loginUrl"}

        if isinstance(raw_enabled, str):
            sso_enabled = raw_enabled.lower() in ("1", "true", "yes", "enabled")
        else:
            sso_enabled = bool(raw_enabled)

        return {"isSSOEnabled": sso_enabled}
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSSOEnabled"
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
            pass_reasons.append(criteriaKey + " check passed - SSO/SAML is enabled for the SentinelOne console")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be determined - insufficient data in API response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the integration is connected to the correct SentinelOne /sso endpoint.")
        else:
            fail_reasons.append(criteriaKey + " check failed - SSO is not enabled")
            recommendations.append("Enable SSO/SAML in the SentinelOne console under Settings > SSO to enforce centralized identity provider authentication.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
