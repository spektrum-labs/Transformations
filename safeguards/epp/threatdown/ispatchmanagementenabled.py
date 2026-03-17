"""
Transformation: isPatchManagementEnabled
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether patch management and vulnerability scanning processes are enabled in ThreatDown policies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementEnabled", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if patch management is enabled in ThreatDown policies."""
    try:
        policies = []
        if isinstance(data, list):
            policies = data
        elif isinstance(data, dict):
            policies = (
                data.get("policies", []) or
                data.get("data", []) or
                data.get("results", []) or
                []
            )

        if not isinstance(policies, list):
            policies = [policies] if policies else []

        total_policies = len(policies)
        patch_enabled_count = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            # Check vulnerability scanning / patch management settings
            vuln_scan = policy.get("vulnerability_scan", policy.get("vulnerabilityScan", None))
            patch_mgmt = policy.get("patch_management", policy.get("patchManagement", None))
            software_updates = policy.get("software_updates", policy.get("softwareUpdates", None))

            has_patch = False
            for setting in [vuln_scan, patch_mgmt, software_updates]:
                if setting is None:
                    continue
                if isinstance(setting, bool) and setting:
                    has_patch = True
                elif isinstance(setting, dict):
                    enabled = setting.get("enabled", setting.get("active", False))
                    if (isinstance(enabled, bool) and enabled) or str(enabled).lower() in ("true", "1", "enabled"):
                        has_patch = True
                elif str(setting).lower() in ("true", "1", "enabled", "active"):
                    has_patch = True

            if has_patch:
                patch_enabled_count = patch_enabled_count + 1

        is_enabled = patch_enabled_count > 0 and total_policies > 0

        return {
            "isPatchManagementEnabled": is_enabled,
            "totalPolicies": total_policies,
            "patchEnabledPolicies": patch_enabled_count
        }
    except Exception as e:
        return {"isPatchManagementEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPatchManagementEnabled"
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

        if result_value:
            pass_reasons.append(f"Patch management enabled in {extra_fields.get('patchEnabledPolicies', 0)} of {extra_fields.get('totalPolicies', 0)} policies")
        else:
            total = extra_fields.get("totalPolicies", 0)
            if total == 0:
                fail_reasons.append("No policies found in ThreatDown Nebula")
                recommendations.append("Create endpoint protection policies with vulnerability scanning enabled")
            else:
                fail_reasons.append(f"Patch management not enabled in any of {total} policies")
                recommendations.append("Enable vulnerability scanning and patch management in ThreatDown Nebula policies")

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
