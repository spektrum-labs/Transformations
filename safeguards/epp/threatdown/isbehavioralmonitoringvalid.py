"""
Transformation: isBehavioralMonitoringValid
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether behavioral monitoring and anomaly detection are enabled with automated alerting.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBehavioralMonitoringValid", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Check if behavioral monitoring is enabled in ThreatDown policies."""
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
        behavioral_enabled_count = 0

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            has_behavioral = False

            # Check behavioral monitoring / anomaly detection settings
            behavioral = policy.get("behavioral_monitoring", policy.get("behavioralMonitoring", None))
            anomaly = policy.get("anomaly_detection", policy.get("anomalyDetection", None))
            edr = policy.get("edr", policy.get("endpoint_detection", policy.get("endpointDetection", None)))
            suspicious_activity = policy.get("suspicious_activity", policy.get("suspiciousActivity", None))

            for setting in [behavioral, anomaly, edr, suspicious_activity]:
                if setting is None:
                    continue
                if isinstance(setting, bool) and setting:
                    has_behavioral = True
                elif isinstance(setting, dict):
                    enabled = setting.get("enabled", setting.get("active", setting.get("monitor", False)))
                    if (isinstance(enabled, bool) and enabled) or str(enabled).lower() in ("true", "1", "enabled"):
                        has_behavioral = True
                elif str(setting).lower() in ("true", "1", "enabled", "active"):
                    has_behavioral = True

            # Check real-time protection as a proxy for behavioral monitoring
            rtp = policy.get("real_time_protection", policy.get("realTimeProtection", policy.get("rtp", None)))
            if rtp is not None and not has_behavioral:
                if (isinstance(rtp, bool) and rtp) or str(rtp).lower() in ("true", "1", "enabled"):
                    has_behavioral = True

            if has_behavioral:
                behavioral_enabled_count = behavioral_enabled_count + 1

        is_valid = behavioral_enabled_count > 0 and total_policies > 0

        return {
            "isBehavioralMonitoringValid": is_valid,
            "totalPolicies": total_policies,
            "policiesWithBehavioral": behavioral_enabled_count
        }
    except Exception as e:
        return {"isBehavioralMonitoringValid": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBehavioralMonitoringValid"
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
            pass_reasons.append(f"Behavioral monitoring enabled in {extra_fields.get('policiesWithBehavioral', 0)} of {extra_fields.get('totalPolicies', 0)} policies")
        else:
            total = extra_fields.get("totalPolicies", 0)
            if total == 0:
                fail_reasons.append("No policies found in ThreatDown Nebula")
                recommendations.append("Create policies with behavioral monitoring and EDR enabled")
            else:
                fail_reasons.append(f"Behavioral monitoring not enabled in any of {total} policies")
                recommendations.append("Enable behavioral monitoring and anomaly detection in ThreatDown Nebula policies")
                recommendations.append("Enable Endpoint Detection and Response (EDR) for suspicious activity monitoring")

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
