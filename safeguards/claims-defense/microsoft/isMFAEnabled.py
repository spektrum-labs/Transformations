"""
Transformation: isMFAEnabled
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Retrieves the MFA Authentication Methods Policy and returns true if MFA is configured and active for the tenant.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnabled", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


MFA_METHOD_IDS = [
    "microsoftAuthenticator",
    "softwareOath",
    "fido2",
    "hardwareOath",
    "temporaryAccessPass",
    "x509Certificate",
    "windowsHelloForBusiness"
]


def evaluate(data):
    try:
        auth_method_configs = data.get("authenticationMethodConfigurations", [])
        if not isinstance(auth_method_configs, list):
            auth_method_configs = []
        enabled_mfa_methods = []
        for method in auth_method_configs:
            if not isinstance(method, dict):
                continue
            method_id = method.get("id", method.get("oDataType", "")).lower()
            state = method.get("state", "").lower()
            if state == "enabled":
                for mfa_id in MFA_METHOD_IDS:
                    if mfa_id.lower() in method_id:
                        enabled_mfa_methods.append(method.get("id", method_id))
                        break
        mfa_enabled = len(enabled_mfa_methods) > 0
        migration_state = data.get("policyMigrationState", None)
        return {
            "isMFAEnabled": mfa_enabled,
            "enabledMFAMethods": enabled_mfa_methods,
            "enabledMFAMethodCount": len(enabled_mfa_methods),
            "policyMigrationState": migration_state
        }
    except Exception as e:
        return {"isMFAEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("MFA is enabled. At least one MFA authentication method is active in the tenant policy.")
            pass_reasons.append("Enabled MFA methods: " + str(extra_fields.get("enabledMFAMethods", [])))
        else:
            fail_reasons.append("No MFA authentication methods found in enabled state.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one strong MFA method (e.g. Microsoft Authenticator or FIDO2) in the Authentication Methods Policy.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"enabledMFAMethodCount": extra_fields.get("enabledMFAMethodCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
