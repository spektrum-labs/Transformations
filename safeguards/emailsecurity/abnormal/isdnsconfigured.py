"""
Transformation: isDNSConfigured
Vendor: Abnormal Security
Category: Email Security / DNS

Checks if DNS authentication (SPF/DKIM/DMARC) is configured via Abnormal Security.
Evaluates email authentication settings and integration status.
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
                "vendor": "Abnormal Security",
                "category": "Email Security"
            }
        }
    }


def is_dns_record_present(value):
    """Check if a DNS record value indicates the record is configured.
    Handles actual record strings, booleans, and the string 'False'/'None'.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in ("false", "none", "null", "", "no", "0", "no banner found", "not found", "n/a"):
            return False
        return len(stripped) > 0
    return bool(value)


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
                result={criteriaKey: False, "spfConfigured": False, "dkimConfigured": False, "dmarcConfigured": False},
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
            # Normalize keys to lowercase for case-insensitive matching
            lower_data = {k.lower(): v for k, v in data.items()}

            # Check for flat DNS record format: {SPF: "v=spf1...", DKIM: "...", DMARC: "v=DMARC1..."}
            if 'spf' in lower_data or 'dkim' in lower_data or 'dmarc' in lower_data:
                spf_configured = is_dns_record_present(lower_data.get('spf'))
                dkim_configured = is_dns_record_present(lower_data.get('dkim'))
                dmarc_configured = is_dns_record_present(lower_data.get('dmarc'))
                dns_configured = spf_configured and dkim_configured and dmarc_configured
            else:
                # Check Abnormal Security settings for email authentication
                settings = data.get('settings', data)

                # Check for email authentication settings
                email_auth = settings.get('emailAuthentication', settings.get('authentication', {}))
                if isinstance(email_auth, dict):
                    spf = email_auth.get('spf', {})
                    dkim = email_auth.get('dkim', {})
                    dmarc = email_auth.get('dmarc', {})

                    if isinstance(spf, dict):
                        spf_configured = is_dns_record_present(spf.get('enabled', spf.get('configured', False)))
                    else:
                        spf_configured = is_dns_record_present(spf)
                    if isinstance(dkim, dict):
                        dkim_configured = is_dns_record_present(dkim.get('enabled', dkim.get('configured', False)))
                    else:
                        dkim_configured = is_dns_record_present(dkim)
                    if isinstance(dmarc, dict):
                        dmarc_configured = is_dns_record_present(dmarc.get('enabled', dmarc.get('configured', False)))
                    else:
                        dmarc_configured = is_dns_record_present(dmarc)

                    dns_configured = spf_configured or dkim_configured or dmarc_configured
                elif 'integrations' in settings:
                    # If Abnormal has integrations configured, DNS is set up
                    integrations = settings['integrations']
                    if isinstance(integrations, list) and len(integrations) > 0:
                        dns_configured = True

                # If we get a valid response from settings, that implies basic DNS config
                if not dns_configured and isinstance(data, dict) and len(data) > 0:
                    if 'organization' in data or 'account' in data:
                        dns_configured = True

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
                "dmarcConfigured": dmarc_configured
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
            result={criteriaKey: False, "spfConfigured": False, "dkimConfigured": False, "dmarcConfigured": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
