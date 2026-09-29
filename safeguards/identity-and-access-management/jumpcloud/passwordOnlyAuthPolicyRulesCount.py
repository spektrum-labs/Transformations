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

    password_only_rules = []
    enforced_mfa_rules = []
    other_rules = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        disabled = policy.get("disabled")
        if disabled is True:
            continue
        effect = policy.get("effect") or {}
        if not isinstance(effect, dict):
            effect = {}
        action = effect.get("action")
        obligations = effect.get("obligations") or {}
        if not isinstance(obligations, dict):
            obligations = {}
        mfa_obj = obligations.get("mfa") or {}
        if not isinstance(mfa_obj, dict):
            mfa_obj = {}
        mfa_required = mfa_obj.get("required")

        if action == "allow" and not mfa_required:
            password_only_rules.append({
                "id": policy.get("id"),
                "name": policy.get("name"),
                "type": policy.get("type"),
            })
        elif action == "allow" and mfa_required:
            enforced_mfa_rules.append(policy.get("id"))
        else:
            other_rules.append(policy.get("id"))

    count = len(password_only_rules)
    total_policies = len(policies)

    if count > 0:
        names = ", ".join([f"{p.get('name')} (type={p.get('type')})" for p in password_only_rules[:5]])
        pass_reasons = []
        fail_reasons = [
            f"{count} of {total_policies} authentication policy rule(s) allow access with effect.action='allow' and no mfa.required obligation: {names}."
        ]
        recommendations = [
            "Update the identified policy rule(s) to require MFA (set effect.obligations.mfa.required=true) or restrict their scope so password-only authentication is not permitted."
        ]
    else:
        pass_reasons = [
            f"No password-only authentication policy rules found among {total_policies} enabled authn policies; all allow-action rules carry an mfa.required obligation."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "passwordOnlyAuthPolicyRulesCount": count,
        "totalPolicyRulesEvaluated": total_policies,
        "enforcedMfaRulesCount": len(enforced_mfa_rules),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPolicies": total_policies,
            "passwordOnlyRules": count,
            "enforcedMfaRules": len(enforced_mfa_rules),
        },
        metadata={
            "transformationId": "passwordOnlyAuthPolicyRulesCount",
            "vendor": "JumpCloud",
            "category": "Identity and Access Management",
        },
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud authentication policy list proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"passwordOnlyAuthPolicyRulesCount": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "passwordOnlyAuthPolicyRulesCount", "vendor": "JumpCloud",
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
