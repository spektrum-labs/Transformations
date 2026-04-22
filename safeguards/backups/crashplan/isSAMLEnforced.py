"""
Transformation: isSAMLEnforced
Vendor: CrashPlan  |  Category: Backup
Evaluates: Check if SAML SSO is enforced for the organization by examining
the organization security settings authentication method field.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSAMLEnforced", "vendor": "CrashPlan", "category": "Backup"}
        }
    }


def evaluate(data):
    """
    Evaluate SAML enforcement from CrashPlan Org API response.
    The getOrg endpoint returns data.settings which contains authentication
    configuration. We look for ssoAuthEnabled, ssoRequired, or similar fields.
    """
    try:
        # The merged data may contain the org data directly or nested under 'data'
        org_data = data
        if "data" in data and isinstance(data.get("data"), dict):
            org_data = data["data"]

        # Extract settings - may be at top level or under 'settings'
        settings = org_data.get("settings", None)
        if settings is None:
            settings = org_data

        # CrashPlan Org settings SAML/SSO fields to check
        saml_fields = ["ssoAuthEnabled", "ssoRequired", "samlEnabled", "samlRequired",
                       "singleSignOnEnabled", "singleSignOnRequired", "isSamlRequired",
                       "isSsoRequired", "isSamlEnforced", "isSsoEnforced"]

        found_fields = {}
        for field in saml_fields:
            if field in settings:
                found_fields[field] = settings[field]

        # Also check nested security or auth sections
        security = settings.get("security", {}) or {}
        auth_settings = settings.get("authSettings", {}) or {}
        sso_settings = settings.get("ssoSettings", {}) or {}

        for field in saml_fields:
            if field in security:
                found_fields[field] = security[field]
            if field in auth_settings:
                found_fields[field] = auth_settings[field]
            if field in sso_settings:
                found_fields[field] = sso_settings[field]

        # Check for authMode or loginType indicating SAML
        auth_mode = settings.get("authMode", None) or settings.get("loginType", None) or settings.get("authType", None)
        if auth_mode is not None:
            found_fields["authMode"] = auth_mode

        if not found_fields and auth_mode is None:
            return {
                "isSAMLEnforced": None,
                "error": "required fields missing from API response: ssoAuthEnabled, ssoRequired, samlEnabled, samlRequired, authMode and related SSO/SAML settings fields"
            }

        # Determine if SAML is enforced
        # Priority: explicit 'Required'/'Enforced' fields first
        required_fields = ["ssoRequired", "samlRequired", "isSamlRequired", "isSsoRequired",
                           "isSamlEnforced", "isSsoEnforced"]
        for field in required_fields:
            if field in found_fields:
                val = found_fields[field]
                if isinstance(val, bool):
                    return {"isSAMLEnforced": val, "detectedField": field, "detectedValue": str(val)}
                if isinstance(val, str):
                    return {"isSAMLEnforced": val.lower() in ["true", "yes", "1", "required", "enforced"], "detectedField": field, "detectedValue": val}

        # Then check enabled fields
        enabled_fields = ["ssoAuthEnabled", "samlEnabled", "singleSignOnEnabled", "isSamlEnabled", "isSsoEnabled"]
        for field in enabled_fields:
            if field in found_fields:
                val = found_fields[field]
                if isinstance(val, bool):
                    return {"isSAMLEnforced": val, "detectedField": field, "detectedValue": str(val)}
                if isinstance(val, str):
                    return {"isSAMLEnforced": val.lower() in ["true", "yes", "1", "enabled"], "detectedField": field, "detectedValue": val}

        # Check authMode
        if auth_mode is not None:
            auth_mode_lower = str(auth_mode).lower()
            is_saml = "saml" in auth_mode_lower or "sso" in auth_mode_lower
            return {"isSAMLEnforced": is_saml, "detectedField": "authMode", "detectedValue": str(auth_mode)}

        return {
            "isSAMLEnforced": None,
            "error": "required fields missing from API response: ssoAuthEnabled, ssoRequired, samlEnabled, samlRequired, authMode and related SSO/SAML settings fields"
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
        result_value = eval_result.get(criteriaKey, None)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value is None:
            fail_reasons.append(criteriaKey + " could not be determined")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify SAML/SSO settings are accessible via the CrashPlan Org API for " + criteriaKey)
        elif result_value:
            pass_reasons.append("SAML SSO is enforced for the organization")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append("SAML SSO is not enforced for the organization")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            for k, v in extra_fields.items():
                fail_reasons.append(k + ": " + str(v))
            recommendations.append("Enable and enforce SAML SSO in the CrashPlan organization security settings")
        combined_result = {criteriaKey: result_value}
        for k, v in extra_fields.items():
            combined_result[k] = v
        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
