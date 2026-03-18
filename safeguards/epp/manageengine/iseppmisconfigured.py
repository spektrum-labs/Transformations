"""
Transformation: isEPPMisconfigured
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: Whether patch health policies and deployment policies have misconfigured settings.
Source: GET /api/1.4/patch/healthpolicy
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPMisconfigured", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check patch health policy for misconfigurations."""
    try:
        issues = []

        # Health policy may be a single object or list of policies
        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = (
                data.get("health_policies", []) or
                data.get("healthPolicies", []) or
                data.get("policies", []) or
                data.get("data", []) or
                []
            )
            # If the response itself is a single health policy
            if not policies and (data.get("policy_name") or data.get("policyName") or data.get("health_status")):
                policies = [data]

        if not isinstance(policies, list):
            policies = [policies] if policies else []

        total_policies = len(policies)
        misconfigured_count = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            policy_name = policy.get("policy_name", policy.get("policyName", policy.get("name", "Unknown")))
            policy_issues = []

            # Check if health policy is enabled
            enabled = policy.get("enabled", policy.get("is_enabled", policy.get("status", True)))
            if isinstance(enabled, str):
                enabled = enabled.lower() in ("true", "1", "enabled", "active")
            if not enabled:
                policy_issues.append("health policy disabled")

            # Check patch scan schedule
            scan_enabled = policy.get("scan_enabled", policy.get("scanEnabled", policy.get("auto_scan", None)))
            if scan_enabled is not None:
                if (isinstance(scan_enabled, bool) and not scan_enabled) or str(scan_enabled).lower() in ("false", "0", "disabled"):
                    policy_issues.append("automatic patch scanning disabled")

            # Check notification settings
            notify = policy.get("notify_enabled", policy.get("notifyEnabled", policy.get("notifications", None)))
            if notify is not None:
                if (isinstance(notify, bool) and not notify) or str(notify).lower() in ("false", "0", "disabled"):
                    policy_issues.append("notifications disabled")

            # Check critical patch auto-approval
            auto_approve_critical = policy.get("auto_approve_critical", policy.get("autoApproveCritical", None))
            if auto_approve_critical is not None:
                if (isinstance(auto_approve_critical, bool) and not auto_approve_critical) or str(auto_approve_critical).lower() in ("false", "0"):
                    policy_issues.append("critical patch auto-approval disabled")

            # Check health status thresholds
            health_status = policy.get("health_status", policy.get("healthStatus", ""))
            if isinstance(health_status, str) and health_status.lower() in ("unhealthy", "critical", "red"):
                policy_issues.append(f"health status is {health_status}")

            if policy_issues:
                misconfigured_count = misconfigured_count + 1
                issues.append(f"{policy_name}: {', '.join(policy_issues)}")

        is_misconfigured = misconfigured_count > 0

        return {
            "isEPPMisconfigured": is_misconfigured,
            "totalPolicies": total_policies,
            "misconfiguredCount": misconfigured_count,
            "misconfiguredDetails": issues
        }
    except Exception as e:
        return {"isEPPMisconfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPMisconfigured"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if not result_value:
            total = extra_fields.get("totalPolicies", 0)
            if total == 0:
                fail_reasons.append("No health policies found in Endpoint Central")
                recommendations.append("Configure patch health policies in Endpoint Central admin console")
            else:
                pass_reasons.append(f"All {total} health policies are properly configured")
        else:
            misconfigured = extra_fields.get("misconfiguredCount", 0)
            total = extra_fields.get("totalPolicies", 0)
            details = extra_fields.get("misconfiguredDetails", [])
            fail_reasons.append(f"{misconfigured} of {total} policies have configuration issues")
            for detail in details:
                fail_reasons.append(detail)
            recommendations.append("Review and correct health policy settings in Endpoint Central > Patch Management > Health Policy")
            recommendations.append("Enable automatic patch scanning and critical patch auto-approval")

        return create_response(
            result={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0), "misconfiguredCount": extra_fields.get("misconfiguredCount", 0)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
