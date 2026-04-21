"""
Transformation: EmailSecurityEnabled
Vendor: Google  |  Category: cis-controls-v8-ig1
Evaluates: Checks Cloud Identity Gmail policies (gmail.service_status and gmail.antispam)
to verify that core Gmail email security features are active and enabled for the organization.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "EmailSecurityEnabled", "vendor": "Google", "category": "cis-controls-v8-ig1"}
        }
    }


def is_policy_active(policy):
    """Return True if a policy setting value indicates an enabled/active state."""
    setting = policy.get("setting", {})
    value = setting.get("value", {})
    if not value:
        return False
    for field_name in ["serviceEnabled", "enabled", "enableSpamFilter", "isEnabled", "active"]:
        field_val = value.get(field_name)
        if field_val is True:
            return True
    for field_name in ["serviceStatus", "status", "state"]:
        field_val = value.get(field_name)
        if isinstance(field_val, str) and field_val.upper() in ["ENABLED", "ACTIVE", "ON"]:
            return True
    return False


def evaluate(data):
    """
    Iterate through Cloud Identity policies and check for:
      - gmail.service_status  -> service is ENABLED
      - gmail.antispam        -> spam filter is enabled
    Both should be present and active for a full pass.
    """
    try:
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            policies = []

        total_policies = len(policies)

        service_status_found = False
        service_status_active = False
        antispam_found = False
        antispam_active = False

        gmail_active_policies = []
        gmail_inactive_policies = []

        for policy in policies:
            setting = policy.get("setting", {})
            setting_type = setting.get("type", "")
            if not isinstance(setting_type, str):
                continue

            if setting_type == "gmail.service_status":
                service_status_found = True
                if is_policy_active(policy):
                    service_status_active = True
                    gmail_active_policies.append(setting_type)
                else:
                    gmail_inactive_policies.append(setting_type)

            elif setting_type == "gmail.antispam":
                antispam_found = True
                if is_policy_active(policy):
                    antispam_active = True
                    gmail_active_policies.append(setting_type)
                else:
                    gmail_inactive_policies.append(setting_type)

        if service_status_found and antispam_found:
            email_security_enabled = service_status_active and antispam_active
        elif service_status_found:
            email_security_enabled = service_status_active
        elif antispam_found:
            email_security_enabled = antispam_active
        else:
            email_security_enabled = False

        return {
            "EmailSecurityEnabled": email_security_enabled,
            "totalPoliciesScanned": total_policies,
            "serviceStatusFound": service_status_found,
            "serviceStatusActive": service_status_active,
            "antispamFound": antispam_found,
            "antispamActive": antispam_active,
            "gmailActivePolicies": gmail_active_policies,
            "gmailInactivePolicies": gmail_inactive_policies,
        }
    except Exception as e:
        return {"EmailSecurityEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "EmailSecurityEnabled"
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
        additional_findings = []

        if result_value:
            pass_reasons.append("Gmail email security policies are active and enabled for the organization.")
            if eval_result.get("serviceStatusActive"):
                pass_reasons.append("gmail.service_status policy is ENABLED.")
            if eval_result.get("antispamActive"):
                pass_reasons.append("gmail.antispam policy is active.")
        else:
            if not eval_result.get("serviceStatusFound") and not eval_result.get("antispamFound"):
                fail_reasons.append("No Gmail security policies (gmail.service_status, gmail.antispam) were found in Cloud Identity.")
                recommendations.append("Ensure Gmail is enabled and Cloud Identity policies are returned for your organization.")
            else:
                if eval_result.get("serviceStatusFound") and not eval_result.get("serviceStatusActive"):
                    fail_reasons.append("gmail.service_status policy exists but is not ENABLED.")
                    recommendations.append("Enable the Gmail service in Google Workspace Admin Console under Apps > Google Workspace > Gmail.")
                if eval_result.get("antispamFound") and not eval_result.get("antispamActive"):
                    fail_reasons.append("gmail.antispam policy exists but spam filtering is not active.")
                    recommendations.append("Enable spam filtering in Gmail settings under Apps > Google Workspace > Gmail > Spam, Phishing and Malware.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        inactive = eval_result.get("gmailInactivePolicies", [])
        if inactive:
            additional_findings.append("Inactive Gmail policies found: " + ", ".join(inactive))

        active = eval_result.get("gmailActivePolicies", [])
        if active:
            additional_findings.append("Active Gmail policies found: " + ", ".join(active))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPoliciesScanned": eval_result.get("totalPoliciesScanned", 0),
                "serviceStatusActive": eval_result.get("serviceStatusActive", False),
                "antispamActive": eval_result.get("antispamActive", False),
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
