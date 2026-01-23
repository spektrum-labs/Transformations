"""
Transformation: isDNSConfigured
Vendor: Email Security Provider
Category: Email Security / DNS

Evaluates if DMARC, DKIM and SPF records are set up properly for email authentication.
"""

import json
import ast
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
                "vendor": "Email Security Provider",
                "category": "Email Security"
            }
        }
    }


def _parse_input(input):
    if isinstance(input, str):
        # First try to parse as literal Python string representation
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass

        # If that fails, try to parse as JSON
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Input string is neither valid Python literal nor JSON")

    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    is_dmarc_configured = False
    is_dkim_configured = False
    is_spf_configured = False

    try:
        input = _parse_input(input)

        # Check for enriched input format
        if isinstance(input, dict) and "data" in input and "validation" in input:
            data = input["data"]
            validation = input["validation"]
        else:
            data = input
            validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

        if validation.get("status") == "failed":
            return create_response(
                result={
                    "isDNSConfigured": False,
                    "isDMARCConfigured": False,
                    "isDKIMConfigured": False,
                    "isSPFConfigured": False
                },
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Unwrap response/result wrappers
        if isinstance(data, dict) and 'response' in data:
            data = _parse_input(data['response'])
        if isinstance(data, dict) and 'result' in data:
            data = _parse_input(data['result'])

        if isinstance(data, dict):
            is_dmarc_configured = True if data.get('DMARC', False) else False
            is_dkim_configured = True if data.get('DKIM', False) else False
            is_spf_configured = True if data.get('SPF', False) else False

        is_dns_configured = is_dmarc_configured and is_dkim_configured and is_spf_configured

        # Build pass/fail reasons
        if is_dmarc_configured:
            pass_reasons.append("DMARC record is configured")
        else:
            fail_reasons.append("DMARC record is not configured")
            recommendations.append("Configure DMARC record for email domain authentication")

        if is_dkim_configured:
            pass_reasons.append("DKIM record is configured")
        else:
            fail_reasons.append("DKIM record is not configured")
            recommendations.append("Configure DKIM record for email signing")

        if is_spf_configured:
            pass_reasons.append("SPF record is configured")
        else:
            fail_reasons.append("SPF record is not configured")
            recommendations.append("Configure SPF record to specify authorized mail servers")

        if is_dns_configured:
            pass_reasons.insert(0, "All email DNS records (DMARC, DKIM, SPF) are properly configured")

        return create_response(
            result={
                "isDMARCConfigured": is_dmarc_configured,
                "isDKIMConfigured": is_dkim_configured,
                "isSPFConfigured": is_spf_configured,
                "isDNSConfigured": is_dns_configured
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "dmarcConfigured": is_dmarc_configured,
                "dkimConfigured": is_dkim_configured,
                "spfConfigured": is_spf_configured
            }
        )

    except Exception as e:
        return create_response(
            result={
                "isDNSConfigured": False,
                "isDMARCConfigured": is_dmarc_configured,
                "isDKIMConfigured": is_dkim_configured,
                "isSPFConfigured": is_spf_configured
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
