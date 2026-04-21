"""
Transformation: isSAMLEnforced
Vendor: CrashPlan  |  Category: Backup
Evaluates: Whether SAML SSO authentication is enforced for the organization
           by examining the security settings authentication configuration.
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
                "transformationId": "isSAMLEnforced",
                "vendor": "CrashPlan",
                "category": "Backup"
            }
        }
    }


def evaluate(data):
    try:
        saml_enforced = False
        saml_enabled = False
        sso_required = False
        auth_method = ""

        # Try top-level data wrapper
        settings = data
        if isinstance(data, dict) and "data" in data:
            settings = data["data"]

        # Look for SAML / SSO fields in security settings
        # CrashPlan security settings may contain ssoAuthEnabled, samlEnabled,
        # requireSso, authenticationMethods, or similar keys
        if isinstance(settings, dict):
            # Direct boolean flags
            if settings.get("samlEnabled") or settings.get("samlSsoEnabled"):
                saml_enabled = True

            if settings.get("requireSso") or settings.get("ssoRequired") or settings.get("enforceSso"):
                sso_required = True

            # authenticationMethods list
            auth_methods = settings.get("authenticationMethods", [])
            if isinstance(auth_methods, list):
                for method in auth_methods:
                    if isinstance(method, dict):
                        method_type = method.get("type", "") or method.get("name", "")
                        if "saml" in str(method_type).lower() or "sso" in str(method_type).lower():
                            saml_enabled = True
                            if method.get("required") or method.get("enforced"):
                                sso_required = True

            # authMethod string field
            auth_method = str(settings.get("authMethod", "") or settings.get("loginType", ""))
            if "saml" in auth_method.lower() or "sso" in auth_method.lower():
                saml_enabled = True

            # singleSignOn sub-object
            sso_obj = settings.get("singleSignOn", settings.get("saml", settings.get("sso", None)))
            if isinstance(sso_obj, dict):
                if sso_obj.get("enabled"):
                    saml_enabled = True
                if sso_obj.get("required") or sso_obj.get("enforced") or sso_obj.get("requireSso"):
                    sso_required = True

        saml_enforced = saml_enabled and sso_required

        return {
            "isSAMLEnforced": saml_enforced,
            "samlEnabled": saml_enabled,
            "ssoRequired": sso_required,
            "authMethod": auth_method
        }
    except Exception as e:
        return {"isSAMLEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSAMLEnforced"
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
            pass_reasons.append("SAML SSO authentication is enforced for the organization")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append("SAML SSO authentication is not enforced for the organization")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable and enforce SAML SSO in CrashPlan organization security settings to require single sign-on for all users")
        return create_response(
            result={criteriaKey: result_value, "samlEnabled": extra_fields.get("samlEnabled", False), "ssoRequired": extra_fields.get("ssoRequired", False), "authMethod": extra_fields.get("authMethod", "")},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "samlEnabled": extra_fields.get("samlEnabled", False), "ssoRequired": extra_fields.get("ssoRequired", False)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
