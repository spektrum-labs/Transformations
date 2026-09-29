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


def transform(input):
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

    total_policies = len(policies)
    sso_scoped_relying_parties = {}
    unprotected_ids = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        ptype = policy.get("type") or ""
        targets = policy.get("targets") or {}
        resources = targets.get("resources") or []
        effect = policy.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa_obj = obligations.get("mfa") or {}
        mfa_required = mfa_obj.get("required") or False
        conditions = policy.get("conditions") or {}
        disabled = policy.get("disabled") or False

        if ptype != "sso":
            continue

        for res in resources:
            if not isinstance(res, dict):
                continue
            rtype = res.get("type") or ""
            rid = res.get("id") or ""
            if rtype != "sso" or not rid:
                continue
            sso_scoped_relying_parties[rid] = True
            has_effective_control = (not disabled) and (mfa_required or bool(conditions))
            if not has_effective_control:
                unprotected_ids.append(rid)

    relying_party_trusts_without_access_control_policy_count = len(unprotected_ids)
    total_relying_parties_scoped = len(sso_scoped_relying_parties)

    input_summary = {
        "totalPoliciesEvaluated": total_policies,
        "ssoScopedRelyingParties": total_relying_parties_scoped,
        "unprotectedRelyingPartyCount": relying_party_trusts_without_access_control_policy_count,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_relying_parties_scoped == 0:
        fail_reasons.append(
            "Among the %d authentication policies returned by listAuthnPolicies, none are of type 'sso' with a "
            "targets.resources entry of type 'sso' and a non-empty relying-party id. This endpoint can only "
            "identify a relying party as protected or unprotected when it is referenced by at least one policy; "
            "since zero relying-party-scoped SSO policies exist in this tenant, no relying party trust currently "
            "has a dedicated access control policy attached, and the count below (0) reflects the SSO-scoped "
            "policy targets found rather than the full relying-party inventory (which would require cross-"
            "referencing the SSO applications list)." % total_policies
        )
        recommendations.append(
            "Create explicit SSO-type conditional access policies (targets.resources type='sso') scoped to each "
            "configured relying party (SSO application) so that access control coverage can be verified per "
            "relying party."
        )
    else:
        if relying_party_trusts_without_access_control_policy_count > 0:
            fail_reasons.append(
                "%d of %d SSO-scoped relying party trust target(s) reference a policy that is disabled or has no "
                "mfa.required/conditions obligation (unprotected ids: %s), meaning no effective access control "
                "policy is enforced for those relying parties." % (
                    relying_party_trusts_without_access_control_policy_count,
                    total_relying_parties_scoped,
                    ", ".join(unprotected_ids[:10]),
                )
            )
            recommendations.append(
                "Enable and enforce (set mfa.required=true or add conditions) the conditional access policy "
                "covering the unprotected relying party trust(s) listed above."
            )
        else:
            pass_reasons.append(
                "All %d SSO-scoped relying party trust target(s) found across %d authentication policies are "
                "covered by an enabled policy with mfa.required=true or defined conditions." % (
                    total_relying_parties_scoped, total_policies,
                )
            )

    result = {
        "relyingPartyTrustsWithoutAccessControlPolicyCount": relying_party_trusts_without_access_control_policy_count,
        "totalPoliciesEvaluated": total_policies,
        "ssoScopedRelyingParties": total_relying_parties_scoped,
    }

    metadata = {
        "transformationId": "relyingPartyTrustsWithoutAccessControlPolicyCount",
        "vendor": "JumpCloud",
        "category": "identity-and-access-management",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
