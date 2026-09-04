"""
Transformation: isEPPMisconfigured
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether ThreatDown EPP policies have misconfigured or unhealthy settings.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPMisconfigured", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Assess endpoint-protection policy configuration from GET /nebula/v1/policies.

    Real shape: policies[] -> contents{status, policy{...}, packages[]}. The
    protection settings live inside contents, not at the policy root. The Windows
    "Endpoint Protection" package carries rtp_settings / self_protection /
    protection_update_enabled.
    """
    policies = data.get("policies") or []
    if not isinstance(policies, list):
        policies = []

    total = 0
    configured = 0
    misconfigured = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        total = total + 1
        name = policy.get("name", "Unknown")

        contents = policy.get("contents") or {}
        status_ok = str(contents.get("status", "")).strip().lower() == "ok"
        policy_body = contents.get("policy") or {}
        protect_service = bool(policy_body.get("protect_service"))

        endpoint_protection = None
        for package in (contents.get("packages") or []):
            if isinstance(package, dict) and package.get("product_name") == "Endpoint Protection":
                endpoint_protection = package
                break

        package_enabled = bool(endpoint_protection.get("enabled")) if endpoint_protection else False
        package_policy = (endpoint_protection or {}).get("policy") or {}

        rtp_settings = package_policy.get("rtp_settings") or {}
        realtime_on = False
        for setting_name, setting in rtp_settings.items():
            if isinstance(setting, dict) and setting.get("enabled"):
                realtime_on = True
                break

        self_protection = bool(package_policy.get("self_protection"))
        auto_updates = bool(package_policy.get("protection_update_enabled"))

        missing = []
        if not status_ok:
            missing.append("policy status not ok")
        if not protect_service:
            missing.append("protection service disabled")
        if not package_enabled:
            missing.append("Endpoint Protection package disabled")
        if not realtime_on:
            missing.append("real-time protection disabled")
        if not self_protection:
            missing.append("self-protection disabled")
        if not auto_updates:
            missing.append("protection updates disabled")

        if missing:
            misconfigured.append(name + ": " + ", ".join(missing))
        else:
            configured = configured + 1

    percentage = int(round((configured * 100.0) / total)) if total else 0

    return {
        "isEPPConfigured": total > 0 and configured == total,
        "totalPolicies": total,
        "configuredPolicies": configured,
        "configuredPercentage": percentage,
        "misconfiguredPolicies": misconfigured,
    }


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
                fail_reasons.append("No policies found in ThreatDown Nebula")
                recommendations.append("Create and configure endpoint protection policies in ThreatDown Nebula")
            else:
                pass_reasons.append(f"All {total} ThreatDown policies are properly configured")
        else:
            misconfigured = (extra_fields.get("totalPolicies", 0) - extra_fields.get("configuredPolicies", 0))
            total = extra_fields.get("totalPolicies", 0)
            details = extra_fields.get("misconfiguredPolicies", [])
            fail_reasons.append(f"{misconfigured} of {total} policies have configuration issues")
            for detail in details:
                fail_reasons.append(detail)
            recommendations.append("Review and correct misconfigured policies in the ThreatDown Nebula console")
            recommendations.append("Ensure real-time protection, tamper protection, and scheduled scanning are enabled")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0), "misconfiguredCount": (extra_fields.get("totalPolicies", 0) - extra_fields.get("configuredPolicies", 0))}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
