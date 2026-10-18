"""Transformation: isMFAEnforcedForUsers (JumpCloud listAuthnPolicies)"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    """Create the standardized 5-section transformation response."""
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

    user_facing_types = ["user_portal", "sso", "ldap", "radius"]

    total_policies = len(policies)
    user_facing_policies = []
    enforced_policy_names = []
    disabled_but_enforced_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        p_type = p.get("type") or ""
        if p_type not in user_facing_types:
            continue
        user_facing_policies.append(p)
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa_obl = obligations.get("mfa") or {}
        mfa_required = bool(mfa_obl.get("required"))
        disabled = bool(p.get("disabled"))
        name = p.get("name") or p.get("id") or "unnamed-policy"
        if mfa_required and not disabled:
            enforced_policy_names.append(f"{name} (type={p_type})")
        elif mfa_required and disabled:
            disabled_but_enforced_names.append(f"{name} (type={p_type})")

    is_enforced = len(enforced_policy_names) > 0

    input_summary = {
        "totalPolicies": total_policies,
        "userFacingPolicyCount": len(user_facing_policies),
        "enforcedPolicyCount": len(enforced_policy_names),
        "disabledButEnforcedPolicyCount": len(disabled_but_enforced_names),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        pass_reasons.append(
            "Found %d enabled user-facing authentication policy(ies) with "
            "effect.obligations.mfa.required=true: %s"
            % (len(enforced_policy_names), ", ".join(enforced_policy_names))
        )
        if disabled_but_enforced_names:
            pass_reasons.append(
                "Note: %d additional policy(ies) require MFA but are currently disabled: %s"
                % (len(disabled_but_enforced_names), ", ".join(disabled_but_enforced_names))
            )
    else:
        if total_policies == 0:
            fail_reasons.append(
                "listAuthnPolicies returned no conditional access policies for this tenant, "
                "so no MFA enforcement policy could be found for end-user access."
            )
        elif not user_facing_policies:
            fail_reasons.append(
                "Of %d policy(ies) returned, none target user-facing resource types (%s)."
                % (total_policies, ", ".join(user_facing_types))
            )
        else:
            fail_reasons.append(
                "Of %d user-facing policy(ies) evaluated, none have "
                "effect.obligations.mfa.required=true while enabled (disabled_but_enforced=%d)."
                % (len(user_facing_policies), len(disabled_but_enforced_names))
            )
        recommendations.append(
            "Create or enable a JumpCloud Conditional Access Policy of type 'user_portal' "
            "(or 'sso') with effect.obligations.mfa.required=true so MFA is enforced for "
            "end-user logins."
        )

    result = {
        "isMFAEnforcedForUsers": is_enforced,
        "totalPolicies": total_policies,
        "userFacingPolicyCount": len(user_facing_policies),
        "enforcedPolicyCount": len(enforced_policy_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMFAEnforcedForUsers",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud authentication policy list proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"isMFAEnforcedForUsers": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "isMFAEnforcedForUsers", "vendor": "JumpCloud",
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
