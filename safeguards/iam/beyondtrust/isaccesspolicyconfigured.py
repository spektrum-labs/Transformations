"""
Transformation: isAccessPolicyConfigured
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether at least one active access policy with RequireApproval = True
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAccessPolicyConfigured", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # Normalize to list
        if isinstance(data, dict):
            policies = data.get("AccessPolicies", data.get("items", data.get("results", [])))
        elif isinstance(data, list):
            policies = data
        else:
            return {
                "isAccessPolicyConfigured": False,
                "totalPolicies": 0,
                "approvalPolicyCount": 0,
                "reason": f"Unexpected type: {type(data).__name__}"
            }

        total = len(policies)
        approval_count = 0

        for policy in policies:
            # Check active status: 1 = active, 0 = inactive
            active_status = policy.get("ActiveStatus", 0)
            if isinstance(active_status, str):
                active_status = int(active_status) if active_status.isdigit() else 0

            if active_status != 1:
                continue  # Skip inactive policies

            # Check RequireApproval at top level
            requires_approval = policy.get("RequireApproval", False)
            if isinstance(requires_approval, str):
                requires_approval = requires_approval.lower() in ("true", "yes", "1")

            # Also check nested ApprovalWorkflow structure
            if not requires_approval:
                workflow = policy.get("ApprovalWorkflow", {})
                if isinstance(workflow, dict):
                    nested_approval = workflow.get("RequiresApproval", False)
                    if isinstance(nested_approval, str):
                        nested_approval = nested_approval.lower() in ("true", "yes", "1")
                    requires_approval = bool(nested_approval)

            if bool(requires_approval):
                approval_count += 1

        result = approval_count > 0

        return {
            "isAccessPolicyConfigured": result,
            "totalPolicies": total,
            "approvalPolicyCount": approval_count
        }
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

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Run core evaluation
        eval_result = _evaluate(data)

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
            recommendations.append(f"Review BeyondTrust configuration for {criteriaKey}")

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
