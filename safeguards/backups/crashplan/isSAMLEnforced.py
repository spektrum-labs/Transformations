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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSAMLEnforced", "vendor": "CrashPlan", "category": "backup"}
        }
    }


def safe_dict(val):
    return val if isinstance(val, dict) else {}


def evaluate(data):
    criteriaKey = "isSAMLEnforced"

    org_security = safe_dict(data.get("orgSecurity"))

    if not org_security and isinstance(data, dict):
        if "authType" in data or "authenticationMethod" in data or "ssoEnabled" in data or "samlEnabled" in data:
            org_security = data

    auth_type_raw = org_security.get("authType")
    auth_method_raw = org_security.get("authenticationMethod")
    sso_enabled_raw = org_security.get("ssoEnabled")
    saml_enabled_raw = org_security.get("samlEnabled")

    has_any_field = (
        auth_type_raw is not None
        or auth_method_raw is not None
        or sso_enabled_raw is not None
        or saml_enabled_raw is not None
    )

    if not has_any_field:
        return {
            criteriaKey: None,
            "error": "required fields missing from API response: orgSecurity.authType, orgSecurity.authenticationMethod, orgSecurity.ssoEnabled, orgSecurity.samlEnabled"
        }

    if auth_type_raw is not None:
        if isinstance(auth_type_raw, str):
            auth_type_upper = auth_type_raw.upper()
            if auth_type_upper in ("SSO", "SAML"):
                return {criteriaKey: True, "authType": auth_type_raw, "detectionMethod": "authType"}
            else:
                return {criteriaKey: False, "authType": auth_type_raw, "detectionMethod": "authType"}

    if auth_method_raw is not None:
        if isinstance(auth_method_raw, str):
            method_upper = auth_method_raw.upper()
            if method_upper in ("SSO", "SAML", "SAML2", "SAML_SSO"):
                return {criteriaKey: True, "authenticationMethod": auth_method_raw, "detectionMethod": "authenticationMethod"}
            else:
                return {criteriaKey: False, "authenticationMethod": auth_method_raw, "detectionMethod": "authenticationMethod"}

    if sso_enabled_raw is not None:
        if isinstance(sso_enabled_raw, str):
            sso_enabled = sso_enabled_raw.lower() in ("1", "true", "yes")
        else:
            sso_enabled = bool(sso_enabled_raw)
        return {criteriaKey: sso_enabled, "ssoEnabled": sso_enabled_raw, "detectionMethod": "ssoEnabled"}

    if saml_enabled_raw is not None:
        if isinstance(saml_enabled_raw, str):
            saml_enabled = saml_enabled_raw.lower() in ("1", "true", "yes")
        else:
            saml_enabled = bool(saml_enabled_raw)
        return {criteriaKey: saml_enabled, "samlEnabled": saml_enabled_raw, "detectionMethod": "samlEnabled"}

    return {criteriaKey: None, "error": "could not determine SAML enforcement from available fields"}


def transform(input):
    criteriaKey = "isSAMLEnforced"
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
        additional_findings = []

        if result_value is True:
            pass_reasons.append("SAML/SSO authentication is enforced for the CrashPlan organization")
            detection = extra_fields.get("detectionMethod", "")
            if detection:
                pass_reasons.append("Detected via field: " + detection)
            for k, v in extra_fields.items():
                if k != "detectionMethod":
                    additional_findings.append(k + ": " + str(v))
        elif result_value is False:
            fail_reasons.append("SAML/SSO authentication is NOT enforced for the CrashPlan organization")
            detection = extra_fields.get("detectionMethod", "")
            if detection:
                fail_reasons.append("Evaluated via field: " + detection)
            auth_type = extra_fields.get("authType", extra_fields.get("authenticationMethod", ""))
            if auth_type:
                fail_reasons.append("Current authType: " + str(auth_type))
            recommendations.append("Configure SAML/SSO authentication enforcement in CrashPlan Administration > Organization Security settings to require SSO for all users.")
        else:
            fail_reasons.append("Could not determine SAML enforcement status")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that the getOrgSecurity endpoint is reachable and returns OrgSecurity data")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
