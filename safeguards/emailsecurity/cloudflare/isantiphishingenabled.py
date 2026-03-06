"""
Transformation: isAntiPhishingEnabled
Vendor: Cloudflare Email Security (formerly Area 1)
Category: Email Security / Anti-Phishing

Checks if anti-phishing protection is enabled in Cloudflare Email Security.
Evaluates the investigate endpoint response for detected threats and dispositions
(MALICIOUS, SUSPICIOUS, SPOOF) indicating active scanning.
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
                "vendor": "Cloudflare Email Security",
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
        total_detections = 0
        malicious_count = 0
        suspicious_count = 0
        spoof_count = 0

        if isinstance(data, dict):
            # Cloudflare envelope: {"success": true, "result": [...], "result_info": {...}}
            messages = data.get('result', data.get('results', data.get('messages', [])))
            result_info = data.get('result_info', {})

            if isinstance(messages, list):
                # If the investigate endpoint responds, scanning is active
                anti_phishing_enabled = True
                total_detections = len(messages)

                for msg in messages:
                    if not isinstance(msg, dict):
                        continue
                    disposition = msg.get('final_disposition', '').upper()
                    if disposition == 'MALICIOUS':
                        malicious_count += 1
                    elif disposition == 'SUSPICIOUS':
                        suspicious_count += 1
                    elif disposition == 'SPOOF':
                        spoof_count += 1

            elif isinstance(result_info, dict) and 'total_count' in result_info:
                # Paginated response indicates active scanning
                anti_phishing_enabled = True
                total_detections = result_info.get('total_count', 0)

            # Check success flag as fallback
            elif data.get('success') is True:
                anti_phishing_enabled = True

        if anti_phishing_enabled:
            reason = "Anti-phishing protection is active"
            if total_detections > 0:
                details = []
                if malicious_count > 0:
                    details.append(f"{malicious_count} malicious")
                if suspicious_count > 0:
                    details.append(f"{suspicious_count} suspicious")
                if spoof_count > 0:
                    details.append(f"{spoof_count} spoofed")
                reason += f" ({total_detections} detections: {', '.join(details)})" if details else f" ({total_detections} detections)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Anti-phishing protection is not enabled or not returning detections")
            recommendations.append("Enable Cloudflare Email Security and verify email routing is configured")

        return create_response(
            result={
                criteriaKey: anti_phishing_enabled,
                "totalDetections": total_detections,
                "maliciousCount": malicious_count,
                "suspiciousCount": suspicious_count,
                "spoofCount": spoof_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalDetections": total_detections,
                "maliciousCount": malicious_count,
                "suspiciousCount": suspicious_count,
                "spoofCount": spoof_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
