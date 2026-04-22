"""
Transformation: isSessionMonitoringEnabled
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether the session monitoring subsystem is active and accessible,
confirmed by a successful (non-error) response from the Sessions endpoint.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSessionMonitoringEnabled", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """True if the Sessions endpoint is reachable and returns a non-error response."""
    try:
        if data is None:
            return {"isSessionMonitoringEnabled": False, "sessionCount": 0,
                    "reason": "Null response - Sessions endpoint unreachable or unauthorized"}

        if isinstance(data, dict):
            error_msg = str(data.get("Message", data.get("error", data.get("detail", "")))).lower()
            error_keywords = ["unauthorized", "forbidden", "access denied", "license"]
            is_error_keyword = False
            for keyword in error_keywords:
                if keyword in error_msg:
                    is_error_keyword = True
                    break
            if error_msg and is_error_keyword:
                return {"isSessionMonitoringEnabled": False, "sessionCount": 0, "reason": error_msg}
            status_val = str(data.get("status", "")).lower()
            if status_val == "error":
                return {"isSessionMonitoringEnabled": False, "sessionCount": 0,
                        "reason": "Error response from Sessions endpoint"}
            return {"isSessionMonitoringEnabled": True, "sessionCount": 1}

        if isinstance(data, list):
            session_count = len(data)
            has_video = False
            for s in data:
                if isinstance(s, dict):
                    video_flag = s.get("VideoRecording", False)
                    if isinstance(video_flag, str):
                        video_flag = video_flag.lower() in ("true", "yes", "1")
                    if bool(video_flag):
                        has_video = True
                        break
            return {"isSessionMonitoringEnabled": True, "sessionCount": session_count,
                    "hasVideoRecording": has_video}

        return {"isSessionMonitoringEnabled": False, "sessionCount": 0,
                "reason": "Unexpected response type"}
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
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure the BeyondTrust Auditor role is assigned to the RunAs user and the Sessions endpoint is licensed and accessible.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
