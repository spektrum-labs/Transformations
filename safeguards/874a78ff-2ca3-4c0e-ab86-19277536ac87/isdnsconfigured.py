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
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }



def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

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


        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        is_dmarc = bool(data.get('DMARC', False))
        is_dkim = bool(data.get('DKIM', False))
        is_spf = bool(data.get('SPF', False))
        is_dns_configured = is_dmarc and is_dkim and is_spf

        additional_findings = []

        # Primary criteria: isDNSConfigured (all records present)
        if is_dns_configured:
            pass_reasons.append("All DNS email security records configured: DMARC, DKIM, and SPF")
        else:
            not_configured = []
            if not is_dmarc:
                not_configured.append("DMARC")
            if not is_dkim:
                not_configured.append("DKIM")
            if not is_spf:
                not_configured.append("SPF")
            fail_reasons.append(f"Missing DNS records: {', '.join(not_configured)}")

        # Additional finding: isDMARCConfigured
        if is_dmarc:
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
                "recommendation": "Configure DMARC record to prevent email spoofing"
            })

        # Additional finding: isDKIMConfigured
        if is_dkim:
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
                "recommendation": "Configure DKIM to sign outgoing emails"
            })

        # Additional finding: isSPFConfigured
        if is_spf:
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
                criteriaKey: is_dns_configured,
                "isDMARCConfigured": is_dmarc,
                "isDKIMConfigured": is_dkim,
                "isSPFConfigured": is_spf
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"dmarc": is_dmarc, "dkim": is_dkim, "spf": is_spf}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "isDMARCConfigured": False, "isDKIMConfigured": False, "isSPFConfigured": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
