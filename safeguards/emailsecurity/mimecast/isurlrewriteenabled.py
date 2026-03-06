"""
Transformation: isURLRewriteEnabled
Vendor: Mimecast
Category: Email Security / URL Protection

Ensures that URLs are checked before delivery.
Checks URL rewrite/protection settings, URL defense, safe links, and URL-related policies.
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
                "vendor": "Mimecast",
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

        url_protection_enabled = False
        url_policies_count = 0

        if isinstance(data, dict):
            if 'urlRewriteEnabled' in data or 'urlProtection' in data:
                url_protection_enabled = bool(data.get('urlRewriteEnabled', data.get('urlProtection', False)))
            elif 'urlDefense' in data or 'safeLinks' in data:
                url_protection_enabled = bool(data.get('urlDefense', data.get('safeLinks', False)))
            elif 'enabled' in data:
                url_protection_enabled = bool(data['enabled'])
            elif 'policies' in data:
                policies = data['policies'] if isinstance(data['policies'], list) else []
                url_policies = [p for p in policies if 'url' in str(p).lower() or 'link' in str(p).lower()]
                url_policies_count = len(url_policies)
                url_protection_enabled = url_policies_count > 0

        if url_protection_enabled:
            reason = "URL rewrite/safe links protection is enabled"
            if url_policies_count > 0:
                reason += f" ({url_policies_count} URL policies configured)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("URL rewriting/Safe Links protection is not enabled")
            recommendations.append("Enable URL rewrite protection in Mimecast to scan links before delivery")

        return create_response(
            result={criteriaKey: url_protection_enabled, "urlPolicies": url_policies_count},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"urlProtectionEnabled": url_protection_enabled, "urlPolicies": url_policies_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
