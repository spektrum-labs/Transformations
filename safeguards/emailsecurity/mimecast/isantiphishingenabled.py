"""
Transformation: isAntiPhishingEnabled
Vendor: Mimecast
Category: Email Security / Anti-Phishing

Evaluates whether Mimecast anti-phishing protection is active by checking
impersonation threat detection statistics from /threats/v1/stats/impersonations.
A successful response confirms Targeted Threat Protection is enabled.
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
                "transformationId": "isAntiPhishingEnabled",
                "vendor": "Mimecast",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        antiphishing_enabled = False
        total_detections = 0

        if isinstance(data, dict):
            # /threats/v1/stats/impersonations returns aggregated stats.
            # A successful response (even with zero detections) confirms
            # Targeted Threat Protection / impersonation scanning is active.
            stats = data.get('data', data.get('stats', []))
            if isinstance(stats, list):
                antiphishing_enabled = True
                for entry in stats:
                    if isinstance(entry, dict):
                        total_detections += entry.get('count', 0)
            elif 'totalCount' in data or 'count' in data:
                antiphishing_enabled = True
                total_detections = data.get('totalCount', data.get('count', 0))

        if antiphishing_enabled:
            reason = "Mimecast Targeted Threat Protection is active"
            if total_detections > 0:
                reason += f" ({total_detections} impersonation threats detected)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Unable to confirm Mimecast anti-phishing protection is active")
            recommendations.append(
                "Ensure the Mimecast API application has the 'Threats, Security Events and Data' "
                "product assigned and Targeted Threat Protection is enabled"
            )

        return create_response(
            result={
                criteriaKey: antiphishing_enabled,
                "totalDetections": total_detections
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "antiphishingActive": antiphishing_enabled,
                "totalDetections": total_detections
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
