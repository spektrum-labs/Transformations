"""
Transformation: isDNSConfigured
Vendor: Cloudflare Email Security (formerly Area 1)
Category: Email Security / DNS

Checks if DNS authentication (SPF/DKIM/DMARC) is configured.
Evaluates the response from the Spektrum DNS checking tool which inspects
mail server security records for the domain.
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
                "vendor": "Cloudflare Email Security",
                "category": "Email Security"
            }
        }
    }


def get_protocol(data, name):
    """Return a protocol value without depending on key casing."""
    if name in data:
        return data.get(name)
    for key, value in data.items():
        if isinstance(key, str) and key.lower() == name.lower():
            return value
    return False


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
                result={
                    criteriaKey: False,
                    "spfConfigured": False,
                    "dkimConfigured": False,
                    "dmarcConfigured": False,
                    "isSPFConfigured": False,
                    "isDKIMConfigured": False,
                    "isDMARCConfigured": False
                },
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        dns_configured = False
        spf_configured = False
        dkim_configured = False
        dmarc_configured = False

        if isinstance(data, dict):
            # Response from Spektrum DNS check tool (grunt endpoint)
            settings = data.get('settings', data)

            # Check for email authentication settings
            email_auth = settings.get('emailAuthentication', settings.get('authentication', {}))
            if isinstance(email_auth, dict):
                spf = email_auth.get('spf', {})
                dkim = email_auth.get('dkim', {})
                dmarc = email_auth.get('dmarc', {})

                if isinstance(spf, dict):
                    spf_configured = bool(spf.get('enabled', spf.get('configured', False)))
                elif isinstance(spf, bool):
                    spf_configured = spf

                if isinstance(dkim, dict):
                    dkim_configured = bool(dkim.get('enabled', dkim.get('configured', False)))
                elif isinstance(dkim, bool):
                    dkim_configured = dkim

                if isinstance(dmarc, dict):
                    dmarc_configured = bool(dmarc.get('enabled', dmarc.get('configured', False)))
                elif isinstance(dmarc, bool):
                    dmarc_configured = dmarc

                dns_configured = spf_configured or dkim_configured or dmarc_configured

            # Direct boolean or record-string fields from the DNS helper.
            if not dns_configured:
                spf_configured = bool(get_protocol(data, "SPF"))
                dkim_configured = bool(get_protocol(data, "DKIM"))
                dmarc_configured = bool(get_protocol(data, "DMARC"))
                dns_configured = spf_configured or dkim_configured or dmarc_configured

            # Check DNS records list (from Cloudflare zones DNS endpoint)
            if not dns_configured:
                records = data.get('records', data.get('result', []))
                if isinstance(records, list) and len(records) > 0:
                    for record in records:
                        if not isinstance(record, dict):
                            continue
                        rtype = record.get('type', '').upper()
                        content = record.get('content', '').lower()
                        if rtype == 'TXT':
                            if 'v=spf1' in content:
                                spf_configured = True
                            elif 'v=dkim1' in content:
                                dkim_configured = True
                            elif 'v=dmarc1' in content:
                                dmarc_configured = True
                        elif rtype == 'CNAME' and 'dkim' in record.get('name', '').lower():
                            dkim_configured = True

        # The requirement passes only when all three records exist. The earlier
        # OR checks are retained solely to preserve the legacy source fallback.
        dns_configured = spf_configured and dkim_configured and dmarc_configured

        # Build additional findings for sub-criteria
        if spf_configured:
            additional_findings.append({"metric": "spfConfigured", "status": "pass", "reason": "SPF record is configured"})
        else:
            additional_findings.append({"metric": "spfConfigured", "status": "fail", "reason": "SPF record not configured", "recommendation": "Configure SPF record for email domain"})

        if dkim_configured:
            additional_findings.append({"metric": "dkimConfigured", "status": "pass", "reason": "DKIM record is configured"})
        else:
            additional_findings.append({"metric": "dkimConfigured", "status": "fail", "reason": "DKIM record not configured", "recommendation": "Configure DKIM record for email signing"})

        if dmarc_configured:
            additional_findings.append({"metric": "dmarcConfigured", "status": "pass", "reason": "DMARC record is configured"})
        else:
            additional_findings.append({"metric": "dmarcConfigured", "status": "fail", "reason": "DMARC record not configured", "recommendation": "Configure DMARC record for domain authentication"})

        if dns_configured:
            pass_reasons.append("DNS email authentication is configured")
        else:
            fail_reasons.append("DNS email authentication (SPF/DKIM/DMARC) is not configured")
            recommendations.append("Configure SPF, DKIM, and DMARC records for email authentication")

        return create_response(
            result={
                criteriaKey: dns_configured,
                "spfConfigured": spf_configured,
                "dkimConfigured": dkim_configured,
                "dmarcConfigured": dmarc_configured,
                "isSPFConfigured": spf_configured,
                "isDKIMConfigured": dkim_configured,
                "isDMARCConfigured": dmarc_configured
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "spfConfigured": spf_configured,
                "dkimConfigured": dkim_configured,
                "dmarcConfigured": dmarc_configured
            }
        )

    except Exception as e:
        return create_response(
            result={
                criteriaKey: False,
                "spfConfigured": False,
                "dkimConfigured": False,
                "dmarcConfigured": False,
                "isSPFConfigured": False,
                "isDKIMConfigured": False,
                "isDMARCConfigured": False
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
