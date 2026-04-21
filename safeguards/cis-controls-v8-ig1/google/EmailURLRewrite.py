"""
Transformation: EmailURLRewrite
Vendor: Google  |  Category: cis-controls-v8-ig1
Evaluates: Checks Cloud Identity Gmail policies for URL rewriting and link-scanning
settings (gmail.url_analysis) to verify that email links are scanned and rewritten
before delivery to end users.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "EmailURLRewrite", "vendor": "Google", "category": "cis-controls-v8-ig1"}
        }
    }


def is_url_rewrite_active(value):
    """Determine if a policy value dict indicates URL rewriting is enabled."""
    if not isinstance(value, dict):
        return False
    for field_name in ["enableUrlRewriting", "urlRewriteEnabled", "enabled", "rewriteEnabled",
                       "enableLinkRewriting", "scanUrls", "scanEnabled"]:
        field_val = value.get(field_name)
        if field_val is True:
            return True
    for field_name in ["status", "state", "urlRewriteStatus"]:
        field_val = value.get(field_name)
        if isinstance(field_val, str) and field_val.upper() in ["ENABLED", "ACTIVE", "ON"]:
            return True
    return False


def evaluate(data):
    """
    Iterate through Cloud Identity policies and look for URL analysis / URL rewrite
    settings in Gmail policies. Candidate setting.type values include:
      - gmail.url_analysis
      - gmail.url_rewriting
      - gmail.enhanced_pre_delivery_message_scanning
    Returns True if at least one URL-related policy is found and active.
    """
    try:
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            policies = []

        total_policies = len(policies)
        url_policy_types = [
            "gmail.url_analysis",
            "gmail.url_rewriting",
            "gmail.enhanced_pre_delivery_message_scanning",
        ]

        url_policies_found = []
        url_policies_active = []
        url_policies_inactive = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            setting = policy.get("setting", {})
            if not isinstance(setting, dict):
                continue
            setting_type = setting.get("type", "")
            if not isinstance(setting_type, str):
                continue

            matched = False
            for candidate in url_policy_types:
                if setting_type == candidate:
                    matched = True
                    break
            if not matched and "gmail." in setting_type and "url" in setting_type:
                matched = True

            if matched:
                url_policies_found.append(setting_type)
                value = setting.get("value", {})
                if is_url_rewrite_active(value):
                    url_policies_active.append(setting_type)
                else:
                    url_policies_inactive.append(setting_type)

        url_rewrite_enabled = len(url_policies_active) > 0

        return {
            "EmailURLRewrite": url_rewrite_enabled,
            "totalPoliciesScanned": total_policies,
            "urlPoliciesFound": url_policies_found,
            "urlPoliciesActive": url_policies_active,
            "urlPoliciesInactive": url_policies_inactive,
            "urlPoliciesFoundCount": len(url_policies_found),
            "urlPoliciesActiveCount": len(url_policies_active),
        }
    except Exception as e:
        return {"EmailURLRewrite": False, "error": str(e)}


def transform(input):
    criteriaKey = "EmailURLRewrite"
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

        active_policies = eval_result.get("urlPoliciesActive", [])
        found_policies = eval_result.get("urlPoliciesFound", [])
        inactive_policies = eval_result.get("urlPoliciesInactive", [])

        if result_value:
            pass_reasons.append("Email URL rewriting/scanning is active. Active URL policy/policies: " + ", ".join(active_policies) + ".")
            pass_reasons.append("Email links are being scanned and rewritten before delivery to end users.")
        else:
            if not found_policies:
                fail_reasons.append("No URL analysis or URL rewriting Gmail policies were found in Cloud Identity (expected: gmail.url_analysis or similar).")
                recommendations.append("Enable Enhanced Pre-delivery Message Scanning or URL rewriting in Google Workspace Admin Console under Apps > Google Workspace > Gmail > Safety.")
                recommendations.append("Ensure the Cloud Identity Policies API is returning Gmail policy data for the organization.")
            else:
                fail_reasons.append("URL rewriting Gmail policy/policies found but none are currently active: " + ", ".join(inactive_policies) + ".")
                recommendations.append("Activate URL rewriting settings in Google Workspace Admin Console under Apps > Google Workspace > Gmail > Safety > Links and external images.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        if inactive_policies:
            additional_findings.append("Inactive URL policies detected: " + ", ".join(inactive_policies))
        if active_policies:
            additional_findings.append("Active URL policies: " + ", ".join(active_policies))

        total = eval_result.get("totalPoliciesScanned", 0)
        additional_findings.append("Total Cloud Identity policies scanned: " + str(total))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPoliciesScanned": total,
                "urlPoliciesFoundCount": eval_result.get("urlPoliciesFoundCount", 0),
                "urlPoliciesActiveCount": eval_result.get("urlPoliciesActiveCount", 0),
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
