"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Google  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Whether a strong password policy is enforced in the Google Workspace domain,
           confirmed by the presence of ENFORCE_STRONG_PASSWORD or related admin activity events.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Google", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def get_param_value(params, param_name):
    """Extract the value of a named parameter from a parameters list."""
    for param in params:
        if param.get("name") == param_name:
            return param.get("value", "")
    return ""


def evaluate(data):
    """
    Scans admin audit activity events for password policy enforcement events.
    Specifically looks for ENFORCE_STRONG_PASSWORD with a truthy new_value parameter,
    and also tracks related password policy configuration events.
    """
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        # Target event names indicating password policy enforcement
        enforce_event = "ENFORCE_STRONG_PASSWORD"
        related_policy_events = [
            "CHANGE_PASSWORD_MINIMUM_LENGTH",
            "CHANGE_PASSWORD_REQUIRE_SYMBOLS",
            "CHANGE_PASSWORD_REQUIRE_NUMERIC",
            "CHANGE_PASSWORD_REUSE_INTERVAL",
            "CHANGE_PASSWORD_EXPIRY"
        ]
        truthy_values = ["true", "1", "enabled", "yes", "on"]

        enforce_strong_found = False
        enforce_strong_enabled = False
        related_events_found = []
        most_recent_enforce_value = ""

        for item in items:
            events = item.get("events", [])
            if not isinstance(events, list):
                events = []
            for event in events:
                event_name = event.get("name", "")

                if event_name == enforce_event:
                    enforce_strong_found = True
                    params = event.get("parameters", [])
                    if not isinstance(params, list):
                        params = []
                    new_val = get_param_value(params, "new_value")
                    most_recent_enforce_value = new_val
                    if new_val.lower() in truthy_values:
                        enforce_strong_enabled = True

                if event_name in related_policy_events:
                    if event_name not in related_events_found:
                        related_events_found.append(event_name)

        # Primary determination: ENFORCE_STRONG_PASSWORD event with truthy value
        confirmed = enforce_strong_enabled

        return {
            "confirmPasswordPolicyEnforced": confirmed,
            "enforceStrongPasswordEventFound": enforce_strong_found,
            "enforceStrongPasswordEnabled": enforce_strong_enabled,
            "mostRecentEnforceValue": most_recent_enforce_value,
            "relatedPolicyEventsFound": related_events_found
        }
    except Exception as e:
        return {"confirmPasswordPolicyEnforced": False, "error": str(e)}


def transform(input):
    criteria_key = "confirmPasswordPolicyEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        enforce_found = extra_fields.get("enforceStrongPasswordEventFound", False)
        enforce_enabled = extra_fields.get("enforceStrongPasswordEnabled", False)
        recent_val = extra_fields.get("mostRecentEnforceValue", "")
        related_found = extra_fields.get("relatedPolicyEventsFound", [])

        if result_value:
            pass_reasons.append("ENFORCE_STRONG_PASSWORD admin audit event was found with an enabled value, confirming password policy is enforced.")
            if recent_val:
                pass_reasons.append("Most recent ENFORCE_STRONG_PASSWORD value: " + recent_val)
        else:
            if not enforce_found:
                fail_reasons.append("No ENFORCE_STRONG_PASSWORD admin audit event was found in the activity log.")
                recommendations.append("Enable 'Enforce strong password' in the Google Admin console under Security > Password management.")
                recommendations.append("Note: The absence of this event in the audit log may also indicate the policy was set before the audit retention window.")
            elif enforce_found and not enforce_enabled:
                fail_reasons.append("ENFORCE_STRONG_PASSWORD event was found but the value indicates it is not enabled. Most recent value: " + recent_val)
                recommendations.append("Navigate to Google Admin console > Security > Password management and enable 'Enforce strong password' for all users.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        if len(related_found) > 0:
            additional_findings.append("Related password policy configuration events found: " + ", ".join(related_found))

        result_dict = {criteria_key: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteria_key: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
