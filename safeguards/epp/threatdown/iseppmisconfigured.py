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
    """Check ThreatDown policies for misconfigurations."""
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
        misconfigured_count = 0
        misconfigured_names = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            issues = []
            policy_name = policy.get("name", policy.get("policyName", "Unknown"))

            # Check real-time protection
            rtp = policy.get("real_time_protection", policy.get("realTimeProtection", policy.get("rtp", None)))
            if rtp is not None:
                if (isinstance(rtp, bool) and not rtp) or str(rtp).lower() in ("false", "0", "disabled", "off"):
                    issues.append("real-time protection disabled")

            # Check scan schedule
            scan_schedule = policy.get("scan_schedule", policy.get("scheduledScan", policy.get("scanEnabled", None)))
            if scan_schedule is not None:
                if (isinstance(scan_schedule, bool) and not scan_schedule) or str(scan_schedule).lower() in ("false", "0", "disabled", "off"):
                    issues.append("scheduled scanning disabled")

            # Check tamper protection
            tamper = policy.get("tamper_protection", policy.get("tamperProtection", None))
            if tamper is not None:
                if (isinstance(tamper, bool) and not tamper) or str(tamper).lower() in ("false", "0", "disabled", "off"):
                    issues.append("tamper protection disabled")

            # Check quarantine settings
            quarantine = policy.get("quarantine", policy.get("autoQuarantine", None))
            if quarantine is not None:
                if (isinstance(quarantine, bool) and not quarantine) or str(quarantine).lower() in ("false", "0", "disabled", "off"):
                    issues.append("auto-quarantine disabled")

            if issues:
                misconfigured_count = misconfigured_count + 1
                misconfigured_names.append(f"{policy_name}: {', '.join(issues)}")

        is_misconfigured = misconfigured_count > 0

        return {
            "isEPPMisconfigured": is_misconfigured,
            "totalPolicies": total_policies,
            "misconfiguredCount": misconfigured_count,
            "misconfiguredDetails": misconfigured_names
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
                fail_reasons.append("No policies found in ThreatDown Nebula")
                recommendations.append("Create and configure endpoint protection policies in ThreatDown Nebula")
            else:
                pass_reasons.append(f"All {total} ThreatDown policies are properly configured")
        else:
            misconfigured = extra_fields.get("misconfiguredCount", 0)
            total = extra_fields.get("totalPolicies", 0)
            details = extra_fields.get("misconfiguredDetails", [])
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
            input_summary={criteriaKey: result_value, "totalPolicies": extra_fields.get("totalPolicies", 0), "misconfiguredCount": extra_fields.get("misconfiguredCount", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
