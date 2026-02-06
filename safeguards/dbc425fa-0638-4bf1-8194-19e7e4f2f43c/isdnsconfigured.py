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

        additional_findings = []

        # Primary criteria: isDNSConfigured (all records present)
        if is_dns_configured:
            pass_reasons.append("All email DNS records (DMARC, DKIM, SPF) are properly configured")
        else:
            not_configured = []
            if not is_dmarc_configured:
                not_configured.append("DMARC")
            if not is_dkim_configured:
                not_configured.append("DKIM")
            if not is_spf_configured:
                not_configured.append("SPF")
            fail_reasons.append(f"Missing DNS records: {', '.join(not_configured)}")

        # Additional finding: isDMARCConfigured
        if is_dmarc_configured:
            additional_findings.append({
                "metric": "isDMARCConfigured",
                "status": "pass",
                "reason": "DMARC record is configured"
            })
        else:
            additional_findings.append({
                "metric": "isDMARCConfigured",
                "status": "fail",
                "reason": "DMARC DNS record not found",
                "recommendation": "Configure DMARC record for email domain authentication"
            })

        # Additional finding: isDKIMConfigured
        if is_dkim_configured:
            additional_findings.append({
                "metric": "isDKIMConfigured",
                "status": "pass",
                "reason": "DKIM record is configured"
            })
        else:
            additional_findings.append({
                "metric": "isDKIMConfigured",
                "status": "fail",
                "reason": "DKIM DNS record not found",
                "recommendation": "Configure DKIM record for email signing"
            })

        # Additional finding: isSPFConfigured
        if is_spf_configured:
            additional_findings.append({
                "metric": "isSPFConfigured",
                "status": "pass",
                "reason": "SPF record is configured"
            })
        else:
            additional_findings.append({
                "metric": "isSPFConfigured",
                "status": "fail",
                "reason": "SPF DNS record not found",
                "recommendation": "Configure SPF record to specify authorized mail servers"
            })

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
            additional_findings=additional_findings,
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
