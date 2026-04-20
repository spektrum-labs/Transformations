"""
Transformation: isAntiPhishingEnabled
Vendor: Abnormal Security
Category: Email Security / Anti-Phishing

Checks if anti-phishing protection is enabled in Abnormal Security.
Evaluates threats data, paginated responses, and phishing protection settings.
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
                "vendor": "Abnormal Security",
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

        anti_phishing_enabled = False
        total_threats = 0
        phishing_threats_detected = 0

        if isinstance(data, dict):
            # Abnormal Security threats response
            threats = data.get('threats', data.get('results', []))
            if isinstance(threats, list):
                total_threats = len(threats)
                # If the endpoint responds, anti-phishing is active
                anti_phishing_enabled = True

                phishing_threats = [t for t in threats if isinstance(t, dict) and (
                    'phishing' in t.get('threatType', '').lower() or
                    'phish' in t.get('attackType', '').lower()
                )]
                phishing_threats_detected = len(phishing_threats)
            elif 'total_count' in data or 'pageNumber' in data:
                # Paginated response indicates service is active
                anti_phishing_enabled = True
                total_threats = data.get('total_count', 0)
            elif 'settings' in data:
                settings = data['settings']
                if isinstance(settings, dict):
                    anti_phishing_enabled = settings.get('phishingProtection', {}).get('enabled', False)

        if anti_phishing_enabled:
            reason = "Anti-phishing protection is active"
            if total_threats > 0:
                reason = reason + " (" + str(total_threats) + " threats monitored, " + str(phishing_threats_detected) + " phishing detected)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Anti-phishing protection is not enabled")
            recommendations.append("Enable anti-phishing protection in Abnormal Security")

        return create_response(
            result={
                criteriaKey: anti_phishing_enabled,
                "totalThreats": total_threats,
                "phishingThreatsDetected": phishing_threats_detected
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalThreats": total_threats,
                "phishingThreatsDetected": phishing_threats_detected
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
