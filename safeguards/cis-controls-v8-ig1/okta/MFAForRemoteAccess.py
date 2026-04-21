"""
Transformation: MFAForRemoteAccess
Vendor: Okta  |  Category: cis-controls-v8-ig1
Evaluates: Whether at least one active OKTA_SIGN_ON (global session policy) rule requires
           MFA (requireFactor=true) for remote or any access scenario.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "MFAForRemoteAccess", "vendor": "Okta", "category": "cis-controls-v8-ig1"}
        }
    }


def get_policies_by_type(data, policy_type):
    policies = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("type") == policy_type:
                policies.append(item)
    return policies


def rule_requires_mfa(rule):
    if not isinstance(rule, dict):
        return False
    actions = rule.get("actions", {})
    signon = actions.get("signon", {})
    require_factor = signon.get("requireFactor", False)
    if require_factor is True:
        return True
    return False


def describe_rule_network(rule):
    conditions = rule.get("conditions", {})
    network = conditions.get("network", {})
    connection = network.get("connection", "ANYWHERE")
    return connection


def evaluate(data):
    try:
        sign_on_policies = get_policies_by_type(data, "OKTA_SIGN_ON")
        active_policies = [p for p in sign_on_policies if p.get("status") == "ACTIVE"]
        total_policies = len(sign_on_policies)
        active_count = len(active_policies)

        mfa_rules_found = []
        non_mfa_policies = []

        for policy in active_policies:
            name = policy.get("name", "Unnamed")
            rules = policy.get("rules", [])
            if not isinstance(rules, list):
                rules = []
            policy_has_mfa_rule = False
            for rule in rules:
                if rule.get("status", "ACTIVE") == "INACTIVE":
                    continue
                if rule_requires_mfa(rule):
                    network_ctx = describe_rule_network(rule)
                    rule_name = rule.get("name", "Unnamed Rule")
                    mfa_rules_found.append(name + " -> " + rule_name + " (network: " + network_ctx + ")")
                    policy_has_mfa_rule = True
            if not policy_has_mfa_rule:
                non_mfa_policies.append(name)

        passes = len(mfa_rules_found) > 0

        return {
            "MFAForRemoteAccess": passes,
            "totalSignOnPolicies": total_policies,
            "activeSignOnPoliciesCount": active_count,
            "mfaEnforcingRulesCount": len(mfa_rules_found),
            "mfaEnforcingRules": mfa_rules_found,
            "policiesWithoutMFARules": non_mfa_policies
        }
    except Exception as e:
        return {"MFAForRemoteAccess": False, "error": str(e)}


def transform(input):
    criteriaKey = "MFAForRemoteAccess"
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

        if result_value:
            pass_reasons.append("At least one active OKTA_SIGN_ON policy rule enforces MFA (requireFactor=true).")
            for rule_desc in extra_fields.get("mfaEnforcingRules", []):
                pass_reasons.append("MFA rule: " + rule_desc)
        else:
            fail_reasons.append("No active OKTA_SIGN_ON policy rule requires MFA. Remote access may not be protected by a second factor.")
            for name in extra_fields.get("policiesWithoutMFARules", []):
                additional_findings.append("Sign-on policy with no MFA rule: " + name)
            recommendations.append("Enable requireFactor=true on at least one active global session policy rule in Okta to enforce MFA for remote access.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalSignOnPolicies": extra_fields.get("totalSignOnPolicies", 0),
                "activeSignOnPoliciesCount": extra_fields.get("activeSignOnPoliciesCount", 0),
                "mfaEnforcingRulesCount": extra_fields.get("mfaEnforcingRulesCount", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
