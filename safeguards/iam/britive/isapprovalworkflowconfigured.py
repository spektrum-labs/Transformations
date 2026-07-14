"""
Transformation: isApprovalWorkflowConfigured
Vendor: Britive  |  Category: Identity & Access Management
Evaluates: Whether at least one privileged profile policy in Britive has an
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isApprovalWorkflowConfigured", "vendor": "Britive", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # Britive policy objects have structure:
        # { "id": str, "name": str, "isActive": bool, "accessType": "Allow",
        #   "condition": {...}, "members": {...},
        #   "settings": [ { "settingsType": "APPROVAL"|"JUSTIFICATION"|"IM", ... } ] }
        # Approval is configured as a policy setting, not a top-level flag.
        # Integration layer passes merged { "policies": [...] }

        if isinstance(data, list):
            policies = data
        else:
            policies = (
                data.get("policies") or
                data.get("data") or
                []
            )

        if not isinstance(policies, list):
            return {"isApprovalWorkflowConfigured": False, "reason": "No policy data found"}

        result = False
        approval_policies_count = 0
        active_policies_count = 0

        for policy in policies:
            is_active = policy.get("isActive", True)
            if isinstance(is_active, str):
                is_active = is_active.lower() not in ("false", "0", "no")

            if not is_active:
                continue

            active_policies_count += 1

            has_approval = False
            for setting in (policy.get("settings") or []):
                if str(setting.get("settingsType", "")).upper() == "APPROVAL":
                    has_approval = True
                    break

            if not has_approval:
                # Fall back to the flat shape used by other/older payloads
                approval_required = policy.get("approvalRequired", False)
                if isinstance(approval_required, str):
                    approval_required = approval_required.lower() in ("true", "yes", "1")

                approvers = policy.get("approvers", {})
                has_approvers = False
                if isinstance(approvers, dict):
                    user_approvers = approvers.get("userIds", approvers.get("users", []))
                    tag_approvers = approvers.get("tags", [])
                    has_approvers = (
                        (isinstance(user_approvers, list) and len(user_approvers) > 0) or
                        (isinstance(tag_approvers, list) and len(tag_approvers) > 0)
                    )

                has_approval = bool(approval_required or has_approvers)

            if has_approval:
                approval_policies_count += 1
                result = True

        return {
            "isApprovalWorkflowConfigured": result,
            "activePoliciesChecked": active_policies_count,
            "policiesWithApproval": approval_policies_count,
        }
    except Exception as e:
        return {"isApprovalWorkflowConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isApprovalWorkflowConfigured"
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
                fail_reasons=["Input validation failed"]
            )

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Britive configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
