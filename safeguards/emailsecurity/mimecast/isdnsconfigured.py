"""
Transformation: isDNSConfigured
Vendor: Mimecast
Category: Email Security / DNS

Ensures that DMARC, DKIM and SPF records are set up properly.
Checks DNS record configuration and email authentication settings.
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
                "transformationId": "isDNSConfigured",
                "vendor": "Mimecast",
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
                result={criteriaKey: False, "dmarc": False, "dkim": False, "spf": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        dns_configured = False
        dmarc_configured = False
        dkim_configured = False
        spf_configured = False

        if isinstance(data, dict):
            if 'dmarc' in data or 'dkim' in data or 'spf' in data:
                dmarc_configured = bool(data.get('dmarc'))
                dkim_configured = bool(data.get('dkim'))
                spf_configured = bool(data.get('spf'))
                dns_configured = dmarc_configured and dkim_configured and spf_configured
            elif 'records' in data:
                records = data['records'] if isinstance(data['records'], list) else []
                dns_configured = len(records) >= 3  # Expect DMARC, DKIM, SPF
            elif 'configured' in data or 'enabled' in data:
                dns_configured = bool(data.get('configured', data.get('enabled', False)))
            elif 'emailAuthentication' in data:
                dns_configured = bool(data['emailAuthentication'])

        # Build additional findings for sub-criteria
        if dmarc_configured:
            additional_findings.append({"metric": "dmarcConfigured", "status": "pass", "reason": "DMARC record is configured"})
        else:
            additional_findings.append({"metric": "dmarcConfigured", "status": "fail", "reason": "DMARC record not configured", "recommendation": "Configure DMARC record for domain authentication"})

        if dkim_configured:
            additional_findings.append({"metric": "dkimConfigured", "status": "pass", "reason": "DKIM record is configured"})
        else:
            additional_findings.append({"metric": "dkimConfigured", "status": "fail", "reason": "DKIM record not configured", "recommendation": "Configure DKIM record for email signing"})

        if spf_configured:
            additional_findings.append({"metric": "spfConfigured", "status": "pass", "reason": "SPF record is configured"})
        else:
            additional_findings.append({"metric": "spfConfigured", "status": "fail", "reason": "SPF record not configured", "recommendation": "Configure SPF record for authorized mail servers"})

        if dns_configured:
            pass_reasons.append("All email DNS records (DMARC, DKIM, SPF) are properly configured")
        else:
            not_configured = []
            if not dmarc_configured:
                not_configured.append("DMARC")
            if not dkim_configured:
                not_configured.append("DKIM")
            if not spf_configured:
                not_configured.append("SPF")
            if not_configured:
                fail_reasons.append(f"Missing DNS records: {', '.join(not_configured)}")
            else:
                fail_reasons.append("DNS email authentication is not configured")
            recommendations.append("Configure DMARC, DKIM, and SPF records for email authentication")

        return create_response(
            result={
                criteriaKey: dns_configured,
                "dmarc": dmarc_configured,
                "dkim": dkim_configured,
                "spf": spf_configured
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "dmarcConfigured": dmarc_configured,
                "dkimConfigured": dkim_configured,
                "spfConfigured": spf_configured
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "dmarc": False, "dkim": False, "spf": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
