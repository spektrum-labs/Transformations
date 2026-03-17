"""
Transformation: isRemovableMediaControlled
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether removable media controls are configured and enforced in ThreatDown policies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRemovableMediaControlled", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if removable media scanning/blocking is enabled in ThreatDown policies."""
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
        controlled_count = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            # Check removable media / USB scanning settings
            removable_media = policy.get("removable_media", policy.get("removableMedia", None))
            usb_scan = policy.get("usb_scan", policy.get("usbScan", policy.get("scan_removable_media", None)))
            device_control = policy.get("device_control", policy.get("deviceControl", None))

            is_controlled = False
            for setting in [removable_media, usb_scan, device_control]:
                if setting is None:
                    continue
                if isinstance(setting, bool) and setting:
                    is_controlled = True
                elif isinstance(setting, dict):
                    enabled = setting.get("enabled", setting.get("active", setting.get("block", False)))
                    if (isinstance(enabled, bool) and enabled) or str(enabled).lower() in ("true", "1", "enabled", "block"):
                        is_controlled = True
                elif str(setting).lower() in ("true", "1", "enabled", "block", "active"):
                    is_controlled = True

            # Also check scan settings - scanning removable media on insert
            scan_settings = policy.get("scan_settings", policy.get("scanSettings", {}))
            if isinstance(scan_settings, dict):
                scan_removable = scan_settings.get("scan_removable_media", scan_settings.get("scanRemovableMedia", None))
                if scan_removable is not None:
                    if (isinstance(scan_removable, bool) and scan_removable) or str(scan_removable).lower() in ("true", "1"):
                        is_controlled = True

            if is_controlled:
                controlled_count = controlled_count + 1

        is_result = controlled_count > 0 and total_policies > 0

        return {
            "isRemovableMediaControlled": is_result,
            "totalPolicies": total_policies,
            "policiesWithControl": controlled_count
        }
    except Exception as e:
        return {"isRemovableMediaControlled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isRemovableMediaControlled"
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
            pass_reasons.append(f"Removable media controls enabled in {extra_fields.get('policiesWithControl', 0)} of {extra_fields.get('totalPolicies', 0)} policies")
        else:
            total = extra_fields.get("totalPolicies", 0)
            if total == 0:
                fail_reasons.append("No policies found in ThreatDown Nebula")
                recommendations.append("Create policies with removable media scanning enabled")
            else:
                fail_reasons.append(f"No policies have removable media controls enabled (checked {total} policies)")
                recommendations.append("Enable USB/removable media scanning in ThreatDown Nebula policies")
                recommendations.append("Consider enabling device control to restrict unauthorized removable media")

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
