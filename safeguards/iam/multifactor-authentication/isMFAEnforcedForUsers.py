"""
Transformation: isMFAEnforcedForUsers
Vendor: Multifactor Authentication  |  Category: iam
Evaluates: Evaluate active Duo policies to confirm that MFA is enforced for all users.
           Checks that no policy sets new_user_policy to bypass and that
           require_enrollment_policy is configured to require enrollment.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Multifactor Authentication",
                "category": "iam"
            }
        }
    }


def get_policy_field(policy, field_name, default_val):
    if field_name in policy:
        return policy[field_name]
    sections = policy.get("sections", {})
    if isinstance(sections, dict):
        for section_key in sections:
            section = sections[section_key]
            if isinstance(section, dict) and field_name in section:
                return section[field_name]
    return default_val


def evaluate(data):
    try:
        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            response_val = data.get("response", [])
            if isinstance(response_val, list):
                policies = response_val
            elif isinstance(data.get("policies", None), list):
                policies = data["policies"]

        total_policies = len(policies)
        bypass_policies = []
        no_enrollment_policies = []
        compliant_policies = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            policy_name = policy.get("policy_name", policy.get("name", "Unknown"))

            new_user_val = get_policy_field(policy, "new_user_policy", "")
            enrollment_val = get_policy_field(policy, "require_enrollment_policy",
                             get_policy_field(policy, "enrollment_policy", ""))

            has_bypass = str(new_user_val).lower() == "bypass"
            enrollment_required = str(enrollment_val).lower() in ["require", "required", "enforce", "enforced"]

            if has_bypass:
                bypass_policies.append(policy_name)
            if not enrollment_required and not has_bypass:
                no_enrollment_policies.append(policy_name)
            if not has_bypass and enrollment_required:
                compliant_policies.append(policy_name)

        is_enforced = (
            total_policies > 0
            and len(bypass_policies) == 0
            and len(no_enrollment_policies) == 0
        )

        if total_policies == 0:
            is_enforced = False

        return {
            "isMFAEnforcedForUsers": is_enforced,
            "totalPoliciesEvaluated": total_policies,
            "bypassPoliciesCount": len(bypass_policies),
            "missingEnrollmentPoliciesCount": len(no_enrollment_policies),
            "compliantPoliciesCount": len(compliant_policies),
            "bypassPolicies": bypass_policies,
            "missingEnrollmentPolicies": no_enrollment_policies,
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total = eval_result.get("totalPoliciesEvaluated", 0)
        bypass_count = eval_result.get("bypassPoliciesCount", 0)
        no_enroll_count = eval_result.get("missingEnrollmentPoliciesCount", 0)
        compliant_count = eval_result.get("compliantPoliciesCount", 0)
        if result_value:
            pass_reasons.append("MFA is enforced for users across all evaluated Duo policies")
            pass_reasons.append("Total compliant policies: " + str(compliant_count) + " of " + str(total))
            pass_reasons.append("No policies found with new_user_policy set to bypass")
            pass_reasons.append("All policies require MFA enrollment for new users")
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if total == 0:
                fail_reasons.append("No active Duo policies were found; MFA enforcement cannot be confirmed")
                recommendations.append("Create at least one Duo policy enforcing MFA for all users")
            if bypass_count > 0:
                bypass_names = eval_result.get("bypassPolicies", [])
                fail_reasons.append(
                    str(bypass_count) + " policy/policies have new_user_policy set to bypass: "
                    + ", ".join(bypass_names))
                recommendations.append("Change new_user_policy from bypass to deny or allow in all Duo policies")
            if no_enroll_count > 0:
                no_enroll_names = eval_result.get("missingEnrollmentPolicies", [])
                fail_reasons.append(
                    str(no_enroll_count) + " policy/policies do not enforce enrollment: "
                    + ", ".join(no_enroll_names))
                recommendations.append("Set require_enrollment_policy to require in all Duo policies")
        additional_findings.append("Total policies evaluated: " + str(total))
        additional_findings.append("Compliant policies: " + str(compliant_count))
        additional_findings.append("Policies with bypass: " + str(bypass_count))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPoliciesEvaluated": total,
                "bypassPoliciesCount": bypass_count,
                "missingEnrollmentPoliciesCount": no_enroll_count,
                "compliantPoliciesCount": compliant_count
            })
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
