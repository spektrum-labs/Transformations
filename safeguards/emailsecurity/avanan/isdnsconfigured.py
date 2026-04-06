"""
Transformation: isDNSConfigured
Vendor: Avanan
Category: Email Security

Evaluates if DMARC, DKIM and SPF records are set up properly.
Note: Avanan does not provide DNS data via API.
This expects DNS data from an external DNS lookup source.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDNSConfigured", "vendor": "Avanan", "category": "Email Security"}
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

        is_dmarc_configured = False
        is_dkim_configured = False
        is_spf_configured = False

        # Check for DMARC configuration
        dmarc_data = data.get('DMARC', data.get('dmarc', None))
        if dmarc_data:
            is_dmarc_configured = True
            if isinstance(dmarc_data, dict):
                policy = dmarc_data.get('policy', dmarc_data.get('p', ''))
                if str(policy).lower() in ['none', '']:
                    is_dmarc_configured = False

        # Check for DKIM configuration
        dkim_data = data.get('DKIM', data.get('dkim', None))
        if dkim_data:
            is_dkim_configured = True

        # Check for SPF configuration
        spf_data = data.get('SPF', data.get('spf', None))
        if spf_data:
            is_spf_configured = True

        is_dns_configured = is_dmarc_configured and is_dkim_configured and is_spf_configured

        pass_reasons = []
        fail_reasons = []
        additional_findings = []

        if is_dns_configured:
            pass_reasons.append("All DNS email security records configured: DMARC, DKIM, and SPF")
        else:
            not_configured = []
            if not is_dmarc_configured:
                not_configured.append("DMARC")
            if not is_dkim_configured:
                not_configured.append("DKIM")
            if not is_spf_configured:
                not_configured.append("SPF")
            fail_reasons.append(f"Missing DNS records: {', '.join(not_configured)}")

        return create_response(
            result={
                criteriaKey: is_dns_configured,
                "isDMARCConfigured": is_dmarc_configured,
                "isDKIMConfigured": is_dkim_configured,
                "isSPFConfigured": is_spf_configured
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            input_summary={"dmarc": is_dmarc_configured, "dkim": is_dkim_configured, "spf": is_spf_configured}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "isDMARCConfigured": False, "isDKIMConfigured": False, "isSPFConfigured": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
