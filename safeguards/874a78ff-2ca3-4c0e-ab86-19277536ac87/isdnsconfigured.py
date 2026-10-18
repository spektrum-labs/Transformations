"""
Transformation: isDNSConfigured
Vendor: Microsoft
Category: Email Security / DNS

Evaluates if DMARC, DKIM and SPF records are properly configured for email security.

Not evaluated (every key None, with a collection error) whenever the body does not prove the answer: a vendor
error marker, a body that carries no SPF, DKIM or DMARC answer (an outage or error body from the DNS lookup, an
empty response), a body that answers only some of the three, malformed or unreadable input, and failed input
validation. The lookup always answers all three keys, with a true/false flag or that protocol's record text (SPF
starts with v=spf1, DMARC with v=DMARC1, DKIM is a tag list that carries a p tag, with or without the optional v=DKIM1
and in any tag order, as in "k=rsa; t=s; p=..."; a DKIM record whose p tag is empty is a revoked key and reads False),
so a key that is absent, null or anything else (the text "false" or "error", the record of another protocol, a number, blank text, a list, an
object) means the body is not that answer. A lookup that answered all three and found a record absent (an explicit
false) is a real False.
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


def dkim_tags(text):
    """The tag=value pairs of a DKIM key record as a dict (tag names in lower case), or None when the text is not a
    tag list (a segment without an equals sign, or a tag name that is not a plain word).

    A DKIM key record is a list of tags separated by semicolons (RFC 6376 section 3.6.1). Only p (the public key) is
    required; v is optional and k, t, s, h, n, g may come in any order, so a real record can read "k=rsa; t=s; p=...".
    """
    tags = {}
    for segment in text.split(";"):
        segment = segment.strip()
        if not segment:
            continue
        name, separator, value = segment.partition("=")
        name = name.strip()
        if not separator or not name or not name.replace("_", "").isalnum():
            return None
        tags[name.lower()] = value.strip()
    return tags


def is_record_text(name, text):
    """True only when the text is the record form of the protocol it sits under (compared in lower case)."""
    if name == "SPF":
        return text.startswith("v=spf1")
    if name == "DMARC":
        return text.startswith("v=dmarc1")
    if name == "DKIM":
        # A key record: the p tag is required, the v tag is optional (and names DKIM1 when present), and the tags
        # come in any order ("k=rsa; t=s; p=..."). A v tag that names another protocol (DMARC or SPF text) is not a
        # DKIM record, and a tag list with no p tag publishes no key.
        tags = dkim_tags(text)
        if tags is not None:
            return "p" in tags and tags.get("v", "dkim1") == "dkim1"
        return "v=dkim1" in text or text.startswith("p=")
    return False


def read_answer(name, value):
    """The lookup's answer for one protocol: True or False for a real flag, True for that protocol's record text.

    None for anything else: a word such as "error", "missing" or "false", blank text, the record of another protocol,
    a number, a list or an object. Such a value says nothing about the record, so the read is not evaluated; it is
    never a record found or a record absent."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and is_record_text(name, value.strip().lower()):
        if name == "DKIM":
            tags = dkim_tags(value.strip().lower())
            if tags is not None and "p" in tags and not tags["p"].replace(" ", ""):
                return False  # an empty p tag is a revoked key (RFC 6376): the record is there, no key is usable
        return True
    return None


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
        if not isinstance(data, dict):
            return not_evaluated(
                validation,
                "The DNS lookup returned no SPF, DKIM or DMARC answer (error body, outage or empty response)",
                "No DNS answer was returned, so this check could not be evaluated",
                "Re-evaluate this check once the DNS lookup is available"
            )
        answers = {name: read_answer(name, get_protocol(data, name)) for name in ("SPF", "DKIM", "DMARC")}
        missing = [name for name in ("SPF", "DKIM", "DMARC") if answers[name] is None]
        if len(missing) == 3:
            return not_evaluated(
                validation,
                "The DNS lookup returned no SPF, DKIM or DMARC answer (error body, outage or empty response)",
                "No DNS answer was returned, so this check could not be evaluated",
                "Re-evaluate this check once the DNS lookup is available"
            )
        if missing:
            # The lookup answers all three keys with a flag or a record text, so a key that is absent, null or anything
            # else is a body that is not that answer, not an absent record.
            return not_evaluated(
                validation,
                "The DNS lookup answered only part of SPF, DKIM and DMARC (no usable answer for " + ", ".join(missing) + ")",
                "The DNS answer was incomplete, so this check could not be evaluated",
                "Re-evaluate this check once the DNS lookup is available"
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        is_dmarc = answers['DMARC']
        is_dkim = answers['DKIM']
        is_spf = answers['SPF']
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
