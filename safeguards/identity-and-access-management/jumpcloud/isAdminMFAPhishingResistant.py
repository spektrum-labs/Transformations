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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


PHISHING_RESISTANT_FACTORS = ["WEBAUTHN", "FIDO2", "FIDO", "PIV", "SMARTCARD"]


def transform_evidence(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("results") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    admin_policies = []
    for p in policies:
        if not isinstance(p, dict):
            continue
        ptype = p.get("type") or ""
        targets = p.get("targets") or {}
        resources = targets.get("resources") or []
        is_admin_scope = ptype == "admin_portal"
        if not is_admin_scope:
            for r in resources:
                if isinstance(r, dict) and r.get("type") == "admin_portal":
                    is_admin_scope = True
                    break
        if is_admin_scope:
            admin_policies.append(p)

    phishing_resistant_policy_names = []
    mfa_required_admin_policy_names = []
    for p in admin_policies:
        if p.get("disabled"):
            continue
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa_obj = obligations.get("mfa") or {}
        factors = obligations.get("mfaFactors") or []
        name = p.get("name") or p.get("id") or "unknown"
        if mfa_obj.get("required"):
            mfa_required_admin_policy_names.append(name)
        has_phishing_resistant = any(
            f in PHISHING_RESISTANT_FACTORS for f in factors
        )
        if mfa_obj.get("required") and has_phishing_resistant:
            phishing_resistant_policy_names.append(name)

    is_phishing_resistant = len(phishing_resistant_policy_names) > 0

    total_policies = len(policies)
    total_admin_policies = len(admin_policies)

    input_summary = {
        "totalPolicies": total_policies,
        "adminScopedPolicies": total_admin_policies,
        "mfaRequiredAdminPolicies": len(mfa_required_admin_policy_names),
        "phishingResistantAdminPolicies": len(phishing_resistant_policy_names),
    }

    if is_phishing_resistant:
        pass_reasons = [
            f"Admin-scoped authentication policy/policies {phishing_resistant_policy_names} require MFA "
            f"(effect.obligations.mfa.required=true) with a phishing-resistant factor in "
            f"effect.obligations.mfaFactors (WebAuthn/FIDO2/PIV) among {total_admin_policies} admin-scoped "
            f"policy/policies found in {total_policies} total authn policies."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_admin_policies == 0:
            fail_reasons = [
                f"No admin_portal-scoped authentication policy was found among {total_policies} authn "
                f"policies retrieved; cannot confirm phishing-resistant MFA is required for admin access."
            ]
            recommendations = [
                "Create a JumpCloud Conditional Access Policy scoped to the Admin Portal that requires "
                "MFA with a phishing-resistant factor (WebAuthn/FIDO2) via mfaFactors."
            ]
        else:
            fail_reasons = [
                f"Found {total_admin_policies} admin-scoped policy/policies ({[p.get('name') for p in admin_policies]}) "
                f"but none require MFA with a phishing-resistant factor (WEBAUTHN/FIDO2/PIV) in "
                f"effect.obligations.mfaFactors; mfa.required admin policies: {mfa_required_admin_policy_names}."
            ]
            recommendations = [
                "Update the Admin Portal conditional access policy's effect.obligations.mfaFactors to include "
                "WEBAUTHN (or another phishing-resistant factor) and ensure mfa.required is true."
            ]

    result = {
        "isAdminMFAPhishingResistant": is_phishing_resistant,
        "adminScopedPolicies": total_admin_policies,
        "phishingResistantAdminPolicies": len(phishing_resistant_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAdminMFAPhishingResistant",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud authentication policy list proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"isAdminMFAPhishingResistant": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "isAdminMFAPhishingResistant", "vendor": "JumpCloud",
                  "category": "identity-and-access-management"},
    )


def record_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    return None


def evidence_problem(data):
    policies = record_list(data)
    if policies is None:
        return "No JumpCloud authentication policy list in the response; nothing to evaluate."
    if not all(isinstance(p, dict) and ("effect" in p or "type" in p) for p in policies):
        return "The response is not a list of JumpCloud authentication policies."
    return None


def transform(input):
    data, validation = extract_input(input)
    problem = evidence_problem(data)
    if problem:
        return unevaluated(problem, validation)
    return transform_evidence(input)
