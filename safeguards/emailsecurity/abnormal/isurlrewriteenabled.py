"""
Transformation: isURLRewriteEnabled
Vendor: Abnormal Security
Category: Email Security / URL Protection

Checks if URL rewrite/safe links protection is enabled in Abnormal Security.
Evaluates URL protection settings, remediation actions, and URL-based threat detections.
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
                "transformationId": "isURLRewriteEnabled",
                "vendor": "Abnormal Security",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isURLRewriteEnabled"

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

        url_rewrite_enabled = False
        url_remediation_actions = 0
        url_threats_detected = 0

        if isinstance(data, dict):
            # Check settings for URL protection
            settings = data.get('settings', data)

            # Check URL protection settings
            url_protection = settings.get('urlProtection', settings.get('linkProtection', {}))
            if isinstance(url_protection, dict):
                url_rewrite_enabled = url_protection.get('enabled', False)

            # Check for remediation actions that include URL rewriting
            remediation = settings.get('remediationActions', settings.get('remediation', {}))
            if isinstance(remediation, dict):
                actions = remediation.get('actions', [])
                if isinstance(actions, list):
                    url_actions = [a for a in actions if 'url' in str(a).lower() or 'link' in str(a).lower()]
                    url_remediation_actions = len(url_actions)
                    if url_remediation_actions > 0:
                        url_rewrite_enabled = True

            # Abnormal's core product includes URL analysis
            if not url_rewrite_enabled:
                threats = data.get('threats', data.get('results', []))
                if isinstance(threats, list) and len(threats) > 0:
                    url_threats = [t for t in threats if isinstance(t, dict) and (
                        t.get('attackVector', '').lower() == 'url' or
                        'url' in t.get('threatType', '').lower()
                    )]
                    url_threats_detected = len(url_threats)
                    if url_threats_detected > 0:
                        url_rewrite_enabled = True

        if url_rewrite_enabled:
            reason = "URL rewrite/safe links protection is enabled"
            if url_threats_detected > 0:
                reason += f" ({url_threats_detected} URL threats detected)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("URL rewriting/Safe Links protection is not enabled")
            recommendations.append("Enable URL rewrite to protect users from malicious links in Abnormal Security")

        return create_response(
            result={
                criteriaKey: url_rewrite_enabled,
                "urlRemediationActions": url_remediation_actions,
                "urlThreatsDetected": url_threats_detected
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "urlRewriteEnabled": url_rewrite_enabled,
                "urlRemediationActions": url_remediation_actions,
                "urlThreatsDetected": url_threats_detected
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
