"""
Transformation: isDNSConfigured
Vendor: Email Security Provider
Category: Email Security / DNS

Evaluates if DMARC, DKIM and SPF records are set up properly for email authentication.

Measured: a DNS lookup result that carries at least one of the DMARC, DKIM and SPF answers. A
record the lookup reports as absent (false) is false, so a lookup that found none of the three is false.
A record the lookup does not report at all (the key is missing or null) is not absent, it is unknown:
its key is None, and isDNSConfigured is None unless a record that was reported absent already proves it
false.

Not measured (all four keys None and a dataCollection error, so Token-Service shows Not evaluated,
never Failed): an error or refusal body, a body that is not JSON or not an object, an object that
carries none of the DMARC, DKIM or SPF answers (so it is not a DNS lookup result), a failed input
validation, and this transform's own exception. A lookup that reports only some of the three answers
is partly measured: the keys it did not report are None. When a reported key is false, isDNSConfigured
is false and no dataCollection error is set, so a missing key cannot hide a measured false. Only when no
reported key is false and a key is missing or null is isDNSConfigured None, and only then does the
dataCollection error name the keys that were not reported.
"""

import json
import ast
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isDNSConfigured', 'isDMARCConfigured', 'isDKIMConfigured', 'isSPFConfigured')


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
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


def parse_input(input):
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


def error_text(data):
    """The error message when the body is an error or refusal envelope, else ''."""
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return str(value.get("message") or value.get("status") or value.get("code") or value)
        return "%s %s" % (value, data.get("message") or data.get("error_description") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return ""


def record_state(value):
    """True when the lookup reports the record, False when it reports it absent, None when it does not
    report it at all (a missing or null key). The string "False" is a report of absence, not a record."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("", "false"):
            return False
        return True
    return True if value else False


def unmeasured(reason, validation):
    """The read could not answer: every key None and a dataCollection error says why."""
    return create_response(
        result={
            "isDNSConfigured": None,
            "isDMARCConfigured": None,
            "isDKIMConfigured": None,
            "isSPFConfigured": None
        },
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason]
    )


def transform(input):
    is_dmarc_configured = False
    is_dkim_configured = False
    is_spf_configured = False

    try:
        input = parse_input(input)

        # Check for enriched input format
        if isinstance(input, dict) and "data" in input and "validation" in input:
            data = input["data"]
            validation = input["validation"]
        else:
            data = input
            validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}

        if validation.get("status") == "failed":
            return unmeasured("Input validation failed", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Unwrap response/result wrappers
        if isinstance(data, dict) and 'response' in data:
            data = parse_input(data['response'])
        if isinstance(data, dict) and 'result' in data:
            data = parse_input(data['result'])

        if not isinstance(data, dict):
            return unmeasured("Response is not a DNS lookup result", validation)
        problem = error_text(data)
        if problem:
            return unmeasured(problem, validation)
        if not any(name in data for name in ("DMARC", "DKIM", "SPF")):
            return unmeasured("The response carries no DMARC, DKIM or SPF answer, so it is not a DNS lookup result",
                              validation)

        # A record the lookup reports absent is False; one it does not report (missing or null) is None.
        is_dmarc_configured = record_state(data.get('DMARC'))
        is_dkim_configured = record_state(data.get('DKIM'))
        is_spf_configured = record_state(data.get('SPF'))

        states = [is_dmarc_configured, is_dkim_configured, is_spf_configured]
        if any(state is False for state in states):
            is_dns_configured = False
        elif any(state is None for state in states):
            is_dns_configured = None
        else:
            is_dns_configured = True
        unreported = [name for name, state in (("DMARC", is_dmarc_configured), ("DKIM", is_dkim_configured),
                                               ("SPF", is_spf_configured)) if state is None]

        additional_findings = []

        # Primary criteria: isDNSConfigured (all records present)
        if is_dns_configured:
            pass_reasons.append("All email DNS records (DMARC, DKIM, SPF) are properly configured")
        else:
            not_configured = []
            if is_dmarc_configured is False:
                not_configured.append("DMARC")
            if is_dkim_configured is False:
                not_configured.append("DKIM")
            if is_spf_configured is False:
                not_configured.append("SPF")
            if not_configured:
                fail_reasons.append(f"Missing DNS records: {', '.join(not_configured)}")
            if unreported:
                fail_reasons.append(f"Not measured: the lookup did not report {', '.join(unreported)}")

        for metric, label, state, advice in (
                ("isDMARCConfigured", "DMARC", is_dmarc_configured,
                 "Configure DMARC record for email domain authentication"),
                ("isDKIMConfigured", "DKIM", is_dkim_configured, "Configure DKIM record for email signing"),
                ("isSPFConfigured", "SPF", is_spf_configured,
                 "Configure SPF record to specify authorized mail servers")):
            if state is True:
                additional_findings.append({
                    "metric": metric,
                    "status": "pass",
                    "reason": label + " record is configured"
                })
            elif state is False:
                additional_findings.append({
                    "metric": metric,
                    "status": "fail",
                    "reason": label + " DNS record not found",
                    "recommendation": advice
                })
            else:
                additional_findings.append({
                    "metric": metric,
                    "status": "not evaluated",
                    "reason": label + " was not reported by the DNS lookup"
                })

        api_errors = None
        if is_dns_configured is None:
            # No key is measured False and a key was not reported, so isDNSConfigured itself is None: say it
            # was not measured instead of letting the evaluator grade it as a failure. When a reported key
            # is measured False, isDNSConfigured is False and is not hidden by a missing key.
            api_errors = ["The DNS lookup did not report %s, so %s not evaluated" % (
                ", ".join(unreported), "it was" if len(unreported) == 1 else "they were")]

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
            api_errors=api_errors,
            input_summary={
                "dmarcConfigured": is_dmarc_configured,
                "dkimConfigured": is_dkim_configured,
                "spfConfigured": is_spf_configured
            }
        )

    except Exception as e:
        return create_response(
            result={
                "isDNSConfigured": None,
                "isDMARCConfigured": None,
                "isDKIMConfigured": None,
                "isSPFConfigured": None
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
