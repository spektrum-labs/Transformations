"""
Transformation: isSessionMonitoringEnabled
Vendor: BeyondTrust Privileged Remote Access (PRA)  |  Category: Identity & Access Management
Evaluates: At least one session policy has session_recording enabled, confirming
privileged sessions are being recorded for audit and monitoring.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSessionMonitoringEnabled", "vendor": "BeyondTrust PRA", "category": "Identity & Access Management"}
        }
    }


RECORDING_ON_VALUES = ("allowed", "enabled", "yes", "true", "1")


def _recording_enabled(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val > 0
    if isinstance(val, str):
        return val.lower() in RECORDING_ON_VALUES
    return False


def evaluate(data):
    try:
        if data is None:
            return {"isSessionMonitoringEnabled": False, "recordingPolicyCount": 0, "totalPolicies": 0, "reason": "Null response"}

        # Error dict
        if isinstance(data, dict):
            error_msg = str(data.get("error", data.get("message", ""))).lower()
            if error_msg and any(k in error_msg for k in ("unauthorized", "forbidden", "access denied")):
                return {"isSessionMonitoringEnabled": False, "recordingPolicyCount": 0, "totalPolicies": 0, "reason": error_msg}
            policies = data.get("session_policies", data.get("items", data.get("results", [])))
        elif isinstance(data, list):
            policies = data
        else:
            return {"isSessionMonitoringEnabled": False, "recordingPolicyCount": 0, "totalPolicies": 0, "reason": "Unexpected type"}

        total = len(policies)
        recording_count = 0
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            if _recording_enabled(policy.get("session_recording")):
                recording_count += 1

        return {
            "isSessionMonitoringEnabled": recording_count > 0,
            "recordingPolicyCount": recording_count,
            "totalPolicies": total
        }
    except Exception as e:
        return {"isSessionMonitoringEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSessionMonitoringEnabled"
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

        pass_reasons, fail_reasons, recommendations = [], [], []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable session_recording on at least one PRA session policy to capture privileged session activity")

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
