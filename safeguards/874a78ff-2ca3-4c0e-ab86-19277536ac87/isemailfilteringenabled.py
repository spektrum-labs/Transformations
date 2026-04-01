"""
Transformation: isEmailFilteringEnabled
Vendor: Microsoft Defender for Office 365  |  Category: Email Security
Evaluates: Whether hosted content filter (spam) policies are enabled and
           configured with appropriate actions for spam, phishing, and bulk mail.

Data source: Get-HostedContentFilterPolicy (Exchange Online PowerShell)
Key fields: IsEnabled, SpamAction, HighConfidenceSpamAction, BulkSpamAction,
            PhishSpamAction, HighConfidencePhishAction, BulkThreshold
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEmailFilteringEnabled", "vendor": "Microsoft Defender for Office 365", "category": "Email Security"}
        }
    }


def parse_api_error(raw_error, source=None):
    """Parse raw API error into clean message with recommendation."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"
    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")


def to_bool(val):
    """Convert various truthy representations to bool."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return bool(val)


# Actions that indicate active filtering (not just allowing through)
ACTIVE_ACTIONS = {"MoveToJmf", "Quarantine", "Delete", "Redirect", "AddXHeader"}


def is_policy_filtering(policy):
    """Check if a hosted content filter policy has meaningful filtering actions configured."""
    if not isinstance(policy, dict):
        return False

    # Policy must be enabled
    enabled = policy.get("IsEnabled")
    if enabled is None:
        enabled = policy.get("Enabled")
    if not to_bool(enabled if enabled is not None else False):
        return False

    # Check that key spam/phish actions are set to something protective
    spam_action = policy.get("SpamAction", "")
    high_spam_action = policy.get("HighConfidenceSpamAction", "")
    phish_action = policy.get("PhishSpamAction", "")
    high_phish_action = policy.get("HighConfidencePhishAction", "")

    # At minimum, high confidence spam and phish should have active actions
    has_spam_filtering = high_spam_action in ACTIVE_ACTIONS
    has_phish_filtering = high_phish_action in ACTIVE_ACTIONS

    return has_spam_filtering and has_phish_filtering


def extract_policies(data):
    """Extract policy list from various input shapes."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "policies" in data:
            policies = data["policies"]
            return policies if isinstance(policies, list) else [policies] if policies else []
        if "value" in data:
            value = data["value"]
            return value if isinstance(value, list) else []
    return []


def evaluate(data):
    """Evaluate hosted content filter policies for active email filtering."""
    try:
        policies = extract_policies(data)

        if not policies:
            return {"isEmailFilteringEnabled": False, "error": "No hosted content filter policies found"}

        filtering_policies = []
        non_filtering_policies = []
        findings = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            name = policy.get("Name", policy.get("name", "Unknown"))

            if is_policy_filtering(policy):
                filtering_policies.append(name)
                findings.append(f"{name}: spam/phish filtering active")
            else:
                enabled = policy.get("IsEnabled", policy.get("Enabled"))
                if not to_bool(enabled if enabled is not None else False):
                    non_filtering_policies.append(name)
                    findings.append(f"{name}: policy disabled")
                else:
                    non_filtering_policies.append(name)
                    high_spam = policy.get("HighConfidenceSpamAction", "N/A")
                    high_phish = policy.get("HighConfidencePhishAction", "N/A")
                    findings.append(f"{name}: enabled but weak actions (HighConfSpam={high_spam}, HighConfPhish={high_phish})")

        has_filtering = len(filtering_policies) > 0

        return {
            "isEmailFilteringEnabled": has_filtering,
            "totalPolicies": len(policies),
            "filteringPolicies": len(filtering_policies),
            "filteringPolicyNames": filtering_policies,
            "findings": findings[:10]
        }
    except Exception as e:
        return {"isEmailFilteringEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEmailFilteringEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        # Check for PowerShell/API error
        if isinstance(data, dict) and "PSError" in data:
            raw_error = data.get("PSError", "")
            api_error, recommendation = parse_api_error(raw_error, source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve hosted content filter policies from Microsoft 365"],
                recommendations=[recommendation]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            names = eval_result.get("filteringPolicyNames", [])
            if names:
                pass_reasons.append(f"Active filtering policies: {', '.join(names[:5])}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure hosted content filter policies with Quarantine or MoveToJmf actions for high confidence spam and phishing")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0), "filteringPolicies": extra_fields.get("filteringPolicies", 0)},
            additional_findings=eval_result.get("findings", [])
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
