"""
Transformation: isDNSConfigured
Vendor: Microsoft
Category: Email Security / DNS

Evaluates if DMARC, DKIM and SPF records are properly configured for email security.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isDNSConfigured",
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isDNSConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "isDMARCConfigured": False, "isDKIMConfigured": False, "isSPFConfigured": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        is_dmarc = bool(data.get('DMARC', False))
        is_dkim = bool(data.get('DKIM', False))
        is_spf = bool(data.get('SPF', False))
        is_dns_configured = is_dmarc and is_dkim and is_spf

        # Build pass/fail reasons based on each component
        configured = []
        not_configured = []

        if is_dmarc:
            configured.append("DMARC")
        else:
            not_configured.append("DMARC")

        if is_dkim:
            configured.append("DKIM")
        else:
            not_configured.append("DKIM")

        if is_spf:
            configured.append("SPF")
        else:
            not_configured.append("SPF")

        if is_dns_configured:
            pass_reasons.append("All DNS email security records configured: DMARC, DKIM, and SPF")
        else:
            if configured:
                pass_reasons.append(f"Configured: {', '.join(configured)}")
            fail_reasons.append(f"Missing DNS records: {', '.join(not_configured)}")
            for record in not_configured:
                if record == "DMARC":
                    recommendations.append("Configure DMARC record to prevent email spoofing")
                elif record == "DKIM":
                    recommendations.append("Configure DKIM to sign outgoing emails")
                elif record == "SPF":
                    recommendations.append("Configure SPF record to specify authorized mail servers")

        return create_response(
            result={
                criteriaKey: is_dns_configured,
                "isDMARCConfigured": is_dmarc,
                "isDKIMConfigured": is_dkim,
                "isSPFConfigured": is_spf
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"dmarc": is_dmarc, "dkim": is_dkim, "spf": is_spf}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "isDMARCConfigured": False, "isDKIMConfigured": False, "isSPFConfigured": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
