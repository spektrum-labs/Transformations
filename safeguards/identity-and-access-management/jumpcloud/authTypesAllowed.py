
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


def transform_evidence(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("results") or data.get("policies") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)
    active_policies = 0
    mfa_required_count = 0
    factor_set = set()
    policy_names = []

    for p in policies:
        if not isinstance(p, dict):
            continue
        if p.get("disabled"):
            continue
        active_policies = active_policies + 1
        name = p.get("name") or p.get("id") or "unnamed-policy"
        policy_names.append(name)
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa = obligations.get("mfa") or {}
        if mfa.get("required"):
            mfa_required_count = mfa_required_count + 1
        factors = obligations.get("mfaFactors") or []
        if isinstance(factors, list):
            for f in factors:
                if isinstance(f, str) and f:
                    factor_set.add(f)

    allowed_types = sorted(factor_set)
    # Password / primary credential is always an implicit allowed auth type for
    # any "allow" policy since JumpCloud authenticates username+password first.
    if "PASSWORD" not in allowed_types:
        allowed_types = ["PASSWORD"] + allowed_types

    input_summary = {
        "totalPolicies": total_policies,
        "activePolicies": active_policies,
        "mfaRequiredPolicies": mfa_required_count,
        "distinctMfaFactorTypesFound": sorted(factor_set),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_policies == 0:
        fail_reasons.append(
            "No authentication policies were returned by listAuthnPolicies; unable to determine which auth types are permitted."
        )
        recommendations.append(
            "Configure at least one Conditional Access Policy in JumpCloud (Security > Conditional Access Policies) so allowed authentication types can be evaluated."
        )
    else:
        if factor_set:
            pass_reasons.append(
                f"Active policies ({', '.join(policy_names)}) declare mfaFactors={sorted(factor_set)}, "
                f"and {mfa_required_count} of {active_policies} active policies require MFA (effect.obligations.mfa.required=true)."
            )
        else:
            pass_reasons.append(
                f"{active_policies} active polic{'y' if active_policies == 1 else 'ies'} found "
                f"({', '.join(policy_names)}); {mfa_required_count} require MFA via effect.obligations.mfa.required=true, "
                "but mfaFactors is empty on all of them, meaning JumpCloud's default factor set (TOTP/WebAuthn/Push/Duo) "
                "is permitted rather than a restricted subset."
            )
            recommendations.append(
                "Consider restricting effect.obligations.mfaFactors on active Conditional Access Policies to an explicit "
                "allow-list (e.g. TOTP, WEBAUTHN) rather than leaving it unrestricted."
            )

    result = {
        "authTypesAllowed": allowed_types,
        "totalPolicies": total_policies,
        "activePolicies": active_policies,
        "mfaRequiredPolicies": mfa_required_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "authTypesAllowed",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud authentication policy list proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"authTypesAllowed": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "authTypesAllowed", "vendor": "JumpCloud",
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
    if not [p for p in policies if not p.get("disabled")]:
        return ("No enabled JumpCloud authentication policy; this key's passing answer would come "
                "from an empty list.")
    return None


def transform(input):
    data, validation = extract_input(input)
    problem = evidence_problem(data)
    if problem:
        return unevaluated(problem, validation)
    return transform_evidence(input)
