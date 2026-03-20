"""
Transformation: isSessionMonitoringEnabled
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether the session monitoring subsystem is active and accessible via
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
    """Core evaluation logic extracted from doc transform."""
    try:
        if data is None:
            return {
                "isSessionMonitoringEnabled": False,
                "sessionCount": 0,
                "reason": "Null response — Sessions endpoint unreachable or unauthorized"
            }

        # Error dict indicates a problem (auth failure, permissions, etc.)
        if isinstance(data, dict):
            error_msg = str(data.get("Message", data.get("error", data.get("detail", "")))).lower()
            if error_msg and any(k in error_msg for k in ("unauthorized", "forbidden", "access denied", "license")):
                return {
                    "isSessionMonitoringEnabled": False,
                    "sessionCount": 0,
                    "reason": error_msg
                }
            # Non-error dict (e.g., single session object) — still counts as enabled
            if "status" in data and str(data["status"]).lower() == "error":
                return {
                    "isSessionMonitoringEnabled": False,
                    "sessionCount": 0,
                    "reason": "Error response from Sessions endpoint"
                }
            return {"isSessionMonitoringEnabled": True, "sessionCount": 1}

        # A list response confirms session monitoring is active
        if isinstance(data, list):
            session_count = len(data)

            # Check if any sessions have video recording enabled (diagnostic)
            has_video = any(
                bool(s.get("VideoRecording", False))
                for s in data
                if isinstance(s, dict)
            )

            return {
                "isSessionMonitoringEnabled": True,
                "sessionCount": session_count,
                "hasVideoRecording": has_video
            }

        return {
            "isSessionMonitoringEnabled": False,
            "sessionCount": 0,
            "reason": "Unexpected response type: non-dict/non-list"
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
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review BeyondTrust configuration for {criteriaKey}")

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
