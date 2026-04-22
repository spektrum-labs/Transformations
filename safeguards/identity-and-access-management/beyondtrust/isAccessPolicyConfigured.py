"""
Transformation: isAccessPolicyConfigured
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether at least one active access policy with approval controls
(RequireApproval or nested ApprovalWorkflow) is configured in BeyondTrust.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAccessPolicyConfigured", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """True if at least one active access policy with approval controls exists."""
    try:
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = data.get("AccessPolicies", data.get("items", data.get("results", [])))
            if not isinstance(policies, list):
                policies = []
        else:
            return {"isAccessPolicyConfigured": None, "error": "required fields missing from API response: AccessPolicies"}

        if len(policies) == 0:
            return {"isAccessPolicyConfigured": False, "totalPolicies": 0, "approvalPolicyCount": 0,
                    "reason": "No access policies found"}

        total = len(policies)
        approval_count = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            # Check active status - 1 = active
            active_status = policy.get("ActiveStatus", 1)
            if isinstance(active_status, str):
                if active_status.isdigit():
                    active_status = int(active_status)
                else:
                    active_status = 1
            if active_status == 0:
                continue

            # Top-level RequireApproval flag
            requires_approval = policy.get("RequireApproval", False)
            if isinstance(requires_approval, str):
                requires_approval = requires_approval.lower() in ("true", "yes", "1")
            else:
                requires_approval = bool(requires_approval)

            # Nested ApprovalWorkflow fallback
            if not requires_approval:
                workflow = policy.get("ApprovalWorkflow", {})
                if not isinstance(workflow, dict):
                    workflow = {}
                nested = workflow.get("RequiresApproval", False)
                if isinstance(nested, str):
                    nested = nested.lower() in ("true", "yes", "1")
                else:
                    nested = bool(nested)
                requires_approval = nested

            if requires_approval:
                approval_count = approval_count + 1

        result = approval_count > 0
        return {"isAccessPolicyConfigured": result, "totalPolicies": total, "approvalPolicyCount": approval_count}
    except Exception as e:
        return {"isAccessPolicyConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAccessPolicyConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure at least one active access policy with RequireApproval enabled in BeyondTrust Password Safe.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
