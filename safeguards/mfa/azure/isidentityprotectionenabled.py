"""
Transformation: isIdentityProtectionEnabled
Vendor: Microsoft
Category: Identity Protection

Evaluates if identity protection is enabled by checking for risk detections.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "isIdentityProtectionEnabled",
                "vendor": "Microsoft",
                "category": "Identity Protection"
            }
        }
    }


def transform(input):
    criteriaKey = "isIdentityProtectionEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return create_response(
                result={criteriaKey: False, "riskDetectionCount": 0},
                validation=validation,
                fail_reasons=["Unexpected input format: expected a JSON object"]
            )

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "riskDetectionCount": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        if "error" in data:
            error_info = data.get("error", {})
            inner_error = error_info.get("innerError", {})
            return create_response(
                result={criteriaKey: False, "riskDetectionCount": 0},
                validation={"status": "error", "errors": [error_info.get("message", "API error")], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get("code"), "innerErrorCode": inner_error.get("code") if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Mirrored from safeguards/d9b6f27a-2e67-4b55-a09e-0784c5de9abd/isidentityprotectionenabled.py
        # A clean tenant can have zero risk detections even with Identity Protection licensed and on.
        risk_detections = data.get("value") or []
        if not isinstance(risk_detections, list):
            risk_detections = [risk_detections] if risk_detections else []

        is_enabled = len(risk_detections) > 0

        if is_enabled:
            pass_reasons.append(
                f"Identity protection is enabled with {len(risk_detections)} risk detections configured"
            )
        else:
            fail_reasons.append("No Identity Protection alerts configured or detected")
            recommendations.append("Enable Azure AD Identity Protection to detect and respond to identity-based risks")

        return create_response(
            result={criteriaKey: is_enabled, "riskDetectionCount": len(risk_detections)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"riskDetectionCount": len(risk_detections)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "riskDetectionCount": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
