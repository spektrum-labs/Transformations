"""
Transformation: isDNSConfigured
Vendor: Microsoft
Category: Email Security / DNS

Evaluates if DMARC, DKIM and SPF records are properly configured for email security.

Not evaluated (every key None, with a collection error) whenever the body does not prove the answer: a vendor
error marker, a body that carries no SPF, DKIM or DMARC answer (an outage or error body from the DNS lookup, an
empty response), malformed or unreadable input, and failed input validation. A lookup that answered and found a
record absent is a real False.
"""

import json
from datetime import datetime

RESULT_KEYS = ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured")


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

def not_evaluated(validation, api_error, fail_reason, recommendation, transformation_errors=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={key: None for key in RESULT_KEYS},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[api_error],
        fail_reasons=[fail_reason],
        recommendations=[recommendation]
    )


def get_protocol(data, name):
    """The SPF, DKIM or DMARC answer, whatever the key casing; None when the body does not carry it."""
    if name in data:
        return data.get(name)
    lowered = {key.lower(): value for key, value in data.items() if isinstance(key, str)}
    return lowered.get(name.lower())


def transform(input):
    criteriaKey = "isDNSConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                validation,
                "Could not read the DNS lookup: input validation failed",
                "Input validation failed",
                "Re-evaluate this check once the DNS lookup succeeds"
            )

        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(str(data.get('PSError') or ''), source="Microsoft 365")
            return not_evaluated(
                {"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_error,
                "Could not retrieve data from Microsoft 365",
                recommendation
            )

        # An outage or error body from the DNS lookup, or an empty response, carries no SPF, DKIM or DMARC answer.
        if not isinstance(data, dict) or not any(get_protocol(data, name) is not None for name in ("SPF", "DKIM", "DMARC")):
            return not_evaluated(
                validation,
                "The DNS lookup returned no SPF, DKIM or DMARC answer (error body, outage or empty response)",
                "No DNS answer was returned, so this check could not be evaluated",
                "Re-evaluate this check once the DNS lookup is available"
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        is_dmarc = bool(get_protocol(data, 'DMARC'))
        is_dkim = bool(get_protocol(data, 'DKIM'))
        is_spf = bool(get_protocol(data, 'SPF'))
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
        message = str(e)[:200]  # the text reaches the stored result, so a long one is cut
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            "Could not evaluate the response",
            f"Transformation error: {message}",
            "Re-evaluate this check once the DNS lookup succeeds",
            transformation_errors=[message]
        )
