"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft  |  Category: claims-defense
Evaluates: Retrieves the MFA Enrollment Policy and Conditional Access policies to determine if MFA is enforced for users.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Microsoft", "category": "claims-defense"}
        }
    }


def check_ca_policy_enforces_mfa(policy):
    if not isinstance(policy, dict):
        return False
    state = policy.get("state", "").lower()
    if state != "enabled":
        return False
    grant_controls = policy.get("grantControls", None)
    if not isinstance(grant_controls, dict):
        return False
    built_in_controls = grant_controls.get("builtInControls", [])
    if not isinstance(built_in_controls, list):
        return False
    for control in built_in_controls:
        if isinstance(control, str) and control.lower() in ["mfa", "requiremultifactorauthentication"]:
            return True
    auth_strength = grant_controls.get("authenticationStrength", None)
    if auth_strength and isinstance(auth_strength, dict):
        return True
    return False


def evaluate(data):
    try:
        migration_state = data.get("policyMigrationState", None)
        enforced_via_migration = False
        if migration_state and isinstance(migration_state, str):
            if migration_state.lower() in ["migrationcomplete", "premigration"]:
                enforced_via_migration = True
        ca_policies = data.get("value", [])
        if not isinstance(ca_policies, list):
            ca_policies = []
        mfa_enforcing_policies = []
        for policy in ca_policies:
            if check_ca_policy_enforces_mfa(policy):
                policy_name = policy.get("displayName", policy.get("id", "unknown"))
                mfa_enforcing_policies.append(policy_name)
        enforced_via_ca = len(mfa_enforcing_policies) > 0
        mfa_enforced = enforced_via_ca or enforced_via_migration
        return {
            "isMFAEnforcedForUsers": mfa_enforced,
            "enforcedViaConditionalAccess": enforced_via_ca,
            "enforcedViaMigrationState": enforced_via_migration,
            "mfaEnforcingPolicies": mfa_enforcing_policies,
            "policyMigrationState": migration_state
        }
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"
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
        if result_value:
            pass_reasons.append("MFA is enforced for users.")
            if extra_fields.get("enforcedViaConditionalAccess"):
                pass_reasons.append("Enforced via Conditional Access policies: " + str(extra_fields.get("mfaEnforcingPolicies", [])))
            if extra_fields.get("enforcedViaMigrationState"):
                pass_reasons.append("Policy migration state confirms MFA enforcement: " + str(extra_fields.get("policyMigrationState")))
        else:
            fail_reasons.append("MFA is not enforced for users via Conditional Access or migration state.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create a Conditional Access policy that requires MFA for all users and enable the Authentication Methods Policy migration.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"mfaEnforcingPolicyCount": len(extra_fields.get("mfaEnforcingPolicies", []))})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
