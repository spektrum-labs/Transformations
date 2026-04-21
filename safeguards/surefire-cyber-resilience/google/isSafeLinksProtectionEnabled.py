"""
Transformation: isSafeLinksProtectionEnabled
Vendor: Google  |  Category: Email Security
Evaluates: Whether a Gmail link protection policy (equivalent to Safe Links) such as
           gmail.safety link scanning is present and enabled in Google Workspace.
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
                "transformationId": "isSafeLinksProtectionEnabled",
                "vendor": "Google",
                "category": "Email Security"
            }
        }
    }


def scan_dict_for_links(value_dict):
    """Return True if value_dict contains an explicit link/URL protection flag set to True."""
    explicit_fields = [
        "linksAndExternalImagesEnabled",
        "linkScanningEnabled",
        "safeLinksEnabled",
        "safeLinkEnabled",
        "externalLinksScanningEnabled",
        "linkProtectionEnabled",
        "scanLinksEnabled",
        "urlScanningEnabled",
        "enabledSafeBrowsingForLinks",
        "linksBehindShortenedUrlsEnabled",
        "scanLinkedImagesEnabled",
    ]
    for field in explicit_fields:
        if value_dict.get(field) is True:
            return True
    for key in value_dict:
        lower_key = key.lower()
        if "link" in lower_key and value_dict[key] is True:
            return True
        if "url" in lower_key and value_dict[key] is True:
            return True
    return False


def evaluate(data):
    """Check gmail.safety policies for link/URL scanning configuration."""
    try:
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            policies = []

        safe_links_enabled = False
        safety_policies_checked = 0
        matched_policy_name = ""

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            setting = policy.get("setting", {})
            if not isinstance(setting, dict):
                setting = {}

            setting_type = setting.get("type", "")
            policy_name = policy.get("name", "")

            is_safety = (
                setting_type == "gmail.safety" or
                "safety" in setting_type.lower() or
                "safety" in policy_name.lower()
            )
            if not is_safety:
                continue

            safety_policies_checked = safety_policies_checked + 1

            value = setting.get("value", {})
            if not isinstance(value, dict):
                value = {}

            if scan_dict_for_links(value):
                safe_links_enabled = True
                matched_policy_name = policy_name
                break

            nested_safety = value.get("gmailSafety", {})
            if not isinstance(nested_safety, dict):
                nested_safety = {}
            if scan_dict_for_links(nested_safety):
                safe_links_enabled = True
                matched_policy_name = policy_name
                break

            nested_settings = value.get("settings", {})
            if not isinstance(nested_settings, dict):
                nested_settings = {}
            if scan_dict_for_links(nested_settings):
                safe_links_enabled = True
                matched_policy_name = policy_name
                break

        return {
            "isSafeLinksProtectionEnabled": safe_links_enabled,
            "safetyPoliciesChecked": safety_policies_checked,
            "matchedPolicyName": matched_policy_name,
        }
    except Exception as e:
        return {"isSafeLinksProtectionEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSafeLinksProtectionEnabled"
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Gmail link protection (Safe Links equivalent) is enabled via a gmail.safety policy")
            if extra_fields.get("matchedPolicyName"):
                pass_reasons.append("Matched policy: " + str(extra_fields["matchedPolicyName"]))
        else:
            fail_reasons.append(
                "No active link protection configuration was found in gmail.safety policies"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Enable link protection in Google Workspace Admin Console under "
                "Apps > Google Workspace > Gmail > Safety > Links and external images. "
                "Enable scanning of shortened URLs and linked images."
            )

        full_result = {}
        full_result[criteriaKey] = result_value
        for k in extra_fields:
            full_result[k] = extra_fields[k]

        input_sum = {}
        input_sum[criteriaKey] = result_value
        for k in extra_fields:
            input_sum[k] = extra_fields[k]

        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_sum
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
