"""
Transformation: isSSOEnabled
Vendor: MDR (Sophos)  |  Category: MDR
Evaluates: Whether SSO (Single Sign-On) is enabled for admin accounts in Sophos Central
by inspecting admin login type or identity provider configuration in the administrators list.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "MDR", "category": "MDR"}
        }
    }


def admin_has_sso(admin):
    login_type = admin.get("loginType", "")
    if isinstance(login_type, str) and login_type.lower() in ["sso", "saml", "oauth", "oidc", "federated"]:
        return True
    idp = admin.get("identityProvider", None)
    if idp is not None:
        return True
    idp_id = admin.get("idpId", None)
    if idp_id is not None and idp_id != "":
        return True
    sso_enabled = admin.get("ssoEnabled", None)
    if sso_enabled is True:
        return True
    mfa = admin.get("mfa", None)
    if isinstance(mfa, dict) and mfa.get("enabled", False):
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []
        total_admins = len(items)
        sso_admin_count = 0
        for admin in items:
            if admin_has_sso(admin):
                sso_admin_count = sso_admin_count + 1
        sso_enabled = sso_admin_count > 0
        sso_percentage = 0.0
        if total_admins > 0:
            sso_percentage = (sso_admin_count * 100.0) / total_admins
        return {
            "isSSOEnabled": sso_enabled,
            "totalAdmins": total_admins,
            "ssoEnabledAdmins": sso_admin_count,
            "ssoAdminPercentage": int(sso_percentage * 100 + 0.5) / 100.0
        }
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
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total = extra_fields.get("totalAdmins", 0)
        sso_count = extra_fields.get("ssoEnabledAdmins", 0)
        sso_pct = extra_fields.get("ssoAdminPercentage", 0.0)
        additional_findings.append("Total admins inspected: " + str(total))
        additional_findings.append("Admins with SSO: " + str(sso_count))
        additional_findings.append("SSO admin percentage: " + str(sso_pct) + "%")
        if result_value:
            pass_reasons.append("SSO is enabled for at least one admin account in Sophos Central.")
            pass_reasons.append(str(sso_count) + " of " + str(total) + " admins have SSO configured.")
        else:
            fail_reasons.append("No admin accounts have SSO (Single Sign-On) enabled in Sophos Central.")
            recommendations.append("Configure SSO/Identity Provider integration for admin accounts in Sophos Central under Global Settings > Identity Provider.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalAdmins": total, "ssoEnabledAdmins": sso_count, "ssoAdminPercentage": sso_pct},
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
