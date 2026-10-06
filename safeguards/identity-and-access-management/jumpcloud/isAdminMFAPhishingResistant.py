import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isAdminMFAPhishingResistant',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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


# effect.obligations.mfaFactors is an array of OBJECTS -- [{"type": "WEBAUTHN"}] -- not of strings.
# JumpCloud's own OpenAPI v2 (docs.jumpcloud.com/api/2.0/index.yaml, schema AuthnPolicyObligations)
# gives the type enum as exactly: DURT, WEBAUTHN, PUSH, DUO, TOTP, SMS_OTP.
#
# This list used to be ["WEBAUTHN", "FIDO2", "FIDO", "PIV", "SMARTCARD"] and was tested with
# `f in PHISHING_RESISTANT_FACTORS for f in factors`, comparing a dict against strings. That is
# always False, so the check reported a finding against EVERY JumpCloud tenant, including one
# correctly configured with a WebAuthn-only admin-portal policy. Four of those five values do not
# exist in JumpCloud's API either: a strict search of the 3 MB v2 spec for FIDO, FIDO2, PIV,
# SMARTCARD and SMART_CARD returns nothing. WEBAUTHN (FIDO2 keys, platform authenticators,
# passkeys) is the only phishing-resistant value JumpCloud emits.
#
# DURT is deliberately counted NEITHER way: it appears only in sample payloads with no description
# anywhere in the spec, so it is not claimed as resistant and not held against a tenant. The
# sibling authTypesAllowed.py takes the same position.
PHISHING_RESISTANT_FACTORS = ("WEBAUTHN",)


def factor_types(factors):
    """The factor type strings in an mfaFactors array.

    Tolerates both shapes: the documented array of objects, and a bare array of strings in case a
    tenant or a future version emits one. Anything else contributes nothing.
    """
    out = []
    for f in factors or []:
        if isinstance(f, dict):
            value = f.get("type")
        elif isinstance(f, str):
            value = f
        else:
            value = None
        if value:
            out.append(str(value).strip().upper())
    return out


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
    unspecified_factor_policy_names = []
    for p in admin_policies:
        if p.get("disabled"):
            continue
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa_obj = obligations.get("mfa") or {}
        types = factor_types(obligations.get("mfaFactors"))
        name = p.get("name") or p.get("id") or "unknown"
        if mfa_obj.get("required"):
            mfa_required_admin_policy_names.append(name)
            # mfaFactors is optional. The console also offers "All Enabled", and the org-wide
            # enabled factor list is not exposed by the API, so a policy that requires MFA without
            # naming its factors cannot be graded either way. That is unknown, not a failure.
            if not types:
                unspecified_factor_policy_names.append(name)
        has_phishing_resistant = any(t in PHISHING_RESISTANT_FACTORS for t in types)
        if mfa_obj.get("required") and has_phishing_resistant:
            phishing_resistant_policy_names.append(name)

    is_phishing_resistant = len(phishing_resistant_policy_names) > 0

    # Nothing provable either way: MFA is required on an admin policy but the factors are not named,
    # and no other admin policy names a phishing-resistant one.
    if not is_phishing_resistant and unspecified_factor_policy_names:
        return create_response(
            result={"isAdminMFAPhishingResistant": None,
                    "adminScopedPolicies": len(admin_policies),
                    "phishingResistantAdminPolicies": 0},
            validation=validation,
            fail_reasons=[
                "Admin-scoped policy/policies " + str(unspecified_factor_policy_names)
                + " require MFA but do not name the permitted factors in "
                "effect.obligations.mfaFactors, and JumpCloud does not expose the org-wide enabled "
                "factor list, so whether admin MFA is phishing-resistant was not evaluated."
            ],
            recommendations=[
                "Set the Admin Portal conditional access policy to require a specific factor "
                "(WebAuthn) rather than All Enabled, so the control can be evidenced."
            ],
            input_summary={
                "totalPolicies": len(policies),
                "adminScopedPolicies": len(admin_policies),
                "mfaRequiredAdminPolicies": len(mfa_required_admin_policy_names),
                "phishingResistantAdminPolicies": 0,
                "adminPoliciesWithUnspecifiedFactors": len(unspecified_factor_policy_names),
            },
        )

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
            f"effect.obligations.mfaFactors (WEBAUTHN) among {total_admin_policies} admin-scoped "
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
                "MFA with the WebAuthn factor via effect.obligations.mfaFactors."
            ]
        else:
            fail_reasons = [
                f"Found {total_admin_policies} admin-scoped policy/policies ({[p.get('name') for p in admin_policies]}) "
                f"but none require MFA with the phishing-resistant factor WEBAUTHN in "
                f"effect.obligations.mfaFactors; mfa.required admin policies: {mfa_required_admin_policy_names}."
            ]
            recommendations = [
                "Update the Admin Portal conditional access policy's effect.obligations.mfaFactors to include "
                "WEBAUTHN and ensure mfa.required is true."
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
