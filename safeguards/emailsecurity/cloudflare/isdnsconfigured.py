"""
Transformation: isDNSConfigured
Vendor: Cloudflare Email Security (formerly Area 1)
Category: Email Security / DNS

Checks if DNS authentication (SPF/DKIM/DMARC) is configured.
Evaluates the response from the Spektrum DNS checking tool which inspects
mail server security records for the domain.

Each protocol is read as True (its record is present), False (the lookup states the record is
absent) or None (the body says nothing usable about it: an empty body, an error envelope, a word
such as "error" or "unknown"). The aggregate is True only when all three are True, False as soon as
one is stated absent, and None otherwise. None always travels with a dataCollection error so the
evaluator reads it as Not evaluated. A string such as "False" is read as False, never as present.
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


RESULT_KEYS = (
    "isDNSConfigured",
    "spfConfigured", "dkimConfigured", "dmarcConfigured",
    "isSPFConfigured", "isDKIMConfigured", "isDMARCConfigured",
)
PROTOCOLS = ("SPF", "DKIM", "DMARC")


def get_protocol(data, name):
    """Return a protocol value without depending on key casing; None when the body does not carry it."""
    if name in data:
        return data.get(name)
    for key, value in data.items():
        if isinstance(key, str) and key.lower() == name.lower():
            return value
    return None


def read_flag(value):
    """True or False for a real flag (a bool, or the words true or false in any case); None for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low == "true":
            return True
        if low == "false":
            return False
    return None


def is_record_text(name, text):
    """True only when the text is the record form of the protocol it sits under (compared in lower case)."""
    if name == "SPF":
        return text.startswith("v=spf1")
    if name == "DMARC":
        return text.startswith("v=dmarc1")
    if name == "DKIM":
        return "v=dkim1" in text or text.startswith("p=")
    return False


def read_answer(name, value):
    """The answer for one protocol: a real flag, True for that protocol's record text, None for anything else."""
    flag = read_flag(value)
    if flag is not None:
        return flag
    if isinstance(value, str) and is_record_text(name, value.strip().lower()):
        return True
    return None


def read_block(name, value):
    """An entry of the nested emailAuthentication block: a flag, a record text, or an object with enabled or configured."""
    if isinstance(value, dict):
        for key in ("enabled", "configured"):
            if key in value:
                return read_flag(value.get(key))
        return None
    return read_answer(name, value)


def first_known(*answers):
    """The first answer that is not None; None when no source answered."""
    for answer in answers:
        if answer is not None:
            return answer
    return None


def read_records(records):
    """Protocols whose record is found in a Cloudflare zone DNS records list.

    A list is a page of the zone, so a record that is not in it is unknown, never absent: only a
    record that is found answers (True)."""
    found = {}
    if not isinstance(records, list):
        return found
    for record in records:
        if not isinstance(record, dict):
            continue
        rtype = str(record.get('type') or '').upper()
        content = str(record.get('content') or '').lower()
        name = str(record.get('name') or '').lower()
        if rtype == 'TXT':
            if 'v=spf1' in content:
                found["SPF"] = True
            elif 'v=dkim1' in content:
                found["DKIM"] = True
            elif 'v=dmarc1' in content:
                found["DMARC"] = True
        elif rtype == 'CNAME' and 'dkim' in name:
            found["DKIM"] = True
    return found


def aggregate(states):
    """True when every protocol is True, False when any is stated absent, None when the rest is unknown."""
    if any(state is False for state in states):
        return False
    if all(state is True for state in states):
        return True
    return None


def not_evaluated(validation, api_error, transformation_errors=None, fail_reason=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={key: None for key in RESULT_KEYS},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[api_error],
        fail_reasons=[fail_reason] if fail_reason else [],
        recommendations=["Re-evaluate this check once the DNS lookup is available"]
    )


def transform(input):
    criteriaKey = "isDNSConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(validation, "Could not read the DNS lookup: input validation failed")

        if not isinstance(data, dict):
            return not_evaluated(
                validation,
                "The DNS lookup returned no SPF, DKIM or DMARC answer (empty body, error body or outage)")

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        # Response from the Spektrum DNS check tool (grunt endpoint).
        settings = data.get('settings', data)
        if not isinstance(settings, dict):
            settings = data

        # Nested email authentication settings.
        nested = {name: None for name in PROTOCOLS}
        email_auth = settings.get('emailAuthentication', settings.get('authentication', {}))
        if isinstance(email_auth, dict):
            for name in PROTOCOLS:
                nested[name] = read_block(name, get_protocol(email_auth, name))

        # Direct flag or record-string fields from the DNS helper.
        direct = {name: read_answer(name, get_protocol(data, name)) for name in PROTOCOLS}

        # DNS records list (Cloudflare zones DNS endpoint): a record found answers, a record not found does not.
        records = data.get('records', data.get('result', []))
        from_records = read_records(records)

        answers = {
            name: first_known(nested[name], direct[name], from_records.get(name))
            for name in PROTOCOLS
        }
        spf_configured = answers["SPF"]
        dkim_configured = answers["DKIM"]
        dmarc_configured = answers["DMARC"]
        dns_configured = aggregate([spf_configured, dkim_configured, dmarc_configured])

        unknown = [name for name in PROTOCOLS if answers[name] is None]
        api_errors = []
        if unknown:
            if len(unknown) == len(PROTOCOLS):
                api_errors.append("The DNS lookup returned no SPF, DKIM or DMARC answer (empty body, error body or outage)")
            else:
                api_errors.append(
                    "The DNS lookup gave no usable answer for " + ", ".join(unknown)
                    + ", so those records could not be evaluated")

        # Build additional findings for sub-criteria
        for name, label, advice in (
            ("SPF", "spfConfigured", "Configure SPF record for email domain"),
            ("DKIM", "dkimConfigured", "Configure DKIM record for email signing"),
            ("DMARC", "dmarcConfigured", "Configure DMARC record for domain authentication"),
        ):
            state = answers[name]
            if state is True:
                additional_findings.append({"metric": label, "status": "pass", "reason": f"{name} record is configured"})
            elif state is False:
                additional_findings.append({"metric": label, "status": "fail", "reason": f"{name} record not configured", "recommendation": advice})
            else:
                additional_findings.append({"metric": label, "status": "not_evaluated", "reason": f"No usable {name} answer was returned"})

        if dns_configured is True:
            pass_reasons.append("DNS email authentication is configured")
        elif dns_configured is False:
            fail_reasons.append("DNS email authentication (SPF/DKIM/DMARC) is not configured")
            recommendations.append("Configure SPF, DKIM, and DMARC records for email authentication")
        else:
            recommendations.append("Re-evaluate this check once the DNS lookup is available")

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
            api_errors=api_errors,
            input_summary={
                "spfConfigured": spf_configured,
                "dkimConfigured": dkim_configured,
                "dmarcConfigured": dmarc_configured
            }
        )

    except Exception as e:
        # An error is Not evaluated, never a fail: None plus a dataCollection error.
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            f"Transformation error: {str(e)}",
            transformation_errors=[str(e)])
