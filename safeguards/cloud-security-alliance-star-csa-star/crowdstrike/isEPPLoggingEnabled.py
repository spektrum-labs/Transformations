"""
Transformation: isEPPLoggingEnabled
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Whether CrowdStrike sensor update policies are active (enabled: true),
           ensuring sensors are managed and updated so that endpoint telemetry
           and logging pipelines remain operational for EPP event visibility.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Crowdstrike", "category": "cloud-security-alliance-star-csa-star"}
        }
    }


def is_sensor_update_policy(resource):
    # Sensor update policies have a 'settings' key with sensor-specific fields
    # and do NOT have 'prevention_settings'
    if "prevention_settings" in resource:
        return False
    settings = resource.get("settings", None)
    if settings is not None:
        return True
    # Fallback: check for known sensor update policy fields
    if "build" in resource or "uninstall_protection" in resource:
        return True
    return False


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not resources:
            return {"isEPPLoggingEnabled": False, "totalSensorUpdatePolicies": 0, "enabledSensorUpdatePolicies": 0, "error": "No policy resources found in API response"}

        sensor_policies = [r for r in resources if is_sensor_update_policy(r)]
        total_count = len(sensor_policies)

        if total_count == 0:
            return {"isEPPLoggingEnabled": False, "totalSensorUpdatePolicies": 0, "enabledSensorUpdatePolicies": 0, "error": "No sensor update policies found in merged policy data"}

        enabled_policies = [p for p in sensor_policies if p.get("enabled", False)]
        enabled_count = len(enabled_policies)
        enabled_names = [p.get("name", "unnamed") for p in enabled_policies]

        is_enabled = enabled_count > 0
        return {
            "isEPPLoggingEnabled": is_enabled,
            "totalSensorUpdatePolicies": total_count,
            "enabledSensorUpdatePolicies": enabled_count,
            "enabledPolicyNames": enabled_names
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalSensorUpdatePolicies", 0)
        enabled = eval_result.get("enabledSensorUpdatePolicies", 0)
        names = eval_result.get("enabledPolicyNames", [])

        if result_value:
            pass_reasons.append("At least one CrowdStrike sensor update policy is actively enabled")
            pass_reasons.append("Enabled sensor update policies: " + str(enabled) + " of " + str(total))
            pass_reasons.append("Active sensor update policies ensure endpoint telemetry and logging pipelines remain operational")
            if names:
                additional_findings.append("Enabled sensor update policy names: " + ", ".join(names))
        else:
            fail_reasons.append("No enabled sensor update policies found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one sensor update policy to ensure sensors are managed and updated")
            recommendations.append("Navigate to Endpoint Security > Sensor Update Policies in the Falcon console and enable policies")
            recommendations.append("Active sensor update policies are required to maintain EPP event visibility and logging pipelines")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalSensorUpdatePolicies": total, "enabledSensorUpdatePolicies": enabled}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
