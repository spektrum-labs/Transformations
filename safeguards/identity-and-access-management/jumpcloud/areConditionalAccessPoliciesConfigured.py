"""Transformation: areConditionalAccessPoliciesConfigured (JumpCloud listAuthnPolicies)"""
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
        policies = data.get("results") or data.get("data") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    total_policies = len(policies)
    active_policies = []
    for p in policies:
        if not isinstance(p, dict):
            continue
        if p.get("disabled") is True:
            continue
        active_policies.append(p)

    configured_details = []
    for p in active_policies:
        effect = p.get("effect") or {}
        obligations = effect.get("obligations") or {}
        mfa_req = (obligations.get("mfa") or {}).get("required")
        targets = p.get("targets") or {}
        has_targets = bool(targets.get("userGroups", {}).get("inclusions")) or bool(
            targets.get("users", {}).get("inclusions")
        )
        conditions = p.get("conditions") or {}
        configured_details.append({
            "id": p.get("id"),
            "name": p.get("name"),
            "type": p.get("type"),
            "mfaRequired": bool(mfa_req),
            "hasTargets": has_targets,
            "hasConditions": bool(conditions),
        })

    active_count = len(active_policies)
    is_configured = active_count > 0

    input_summary = {
        "totalPolicies": total_policies,
        "activePolicies": active_count,
    }

    if is_configured:
        names = [d["name"] for d in configured_details if d.get("name")]
        mfa_names = [d["name"] for d in configured_details if d.get("mfaRequired")]
        pass_reasons = [
            f"Found {active_count} enabled (non-disabled) conditional access polic{'y' if active_count == 1 else 'ies'} out of {total_policies} total: {', '.join(names) if names else 'unnamed policies'}."
        ]
        if mfa_names:
            pass_reasons.append(
                f"{len(mfa_names)} of these policies enforce MFA (effect.obligations.mfa.required=true): {', '.join(mfa_names)}."
            )
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No enabled conditional access policies found among {total_policies} policy record(s) returned by listAuthnPolicies."
        ]
        recommendations = [
            "Configure at least one Conditional Access Policy in JumpCloud (Security > Conditional Access Policies) targeting the User Portal or SSO applications, and ensure it is not disabled."
        ]

    result = {
        "areConditionalAccessPoliciesConfigured": is_configured,
        "totalPolicies": total_policies,
        "activePolicies": active_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "areConditionalAccessPoliciesConfigured",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
        additional_findings=configured_details,
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud authentication policy list proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"areConditionalAccessPoliciesConfigured": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "areConditionalAccessPoliciesConfigured", "vendor": "JumpCloud",
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
