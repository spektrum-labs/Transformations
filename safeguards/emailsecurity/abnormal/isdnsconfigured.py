"""
Transformation: isDNSConfigured
Vendor: Abnormal Security  |  Category: emailsecurity
Evaluates: Ensure that DMARC, DKIM and SPF records are set up properly.

isDKIMConfigured / isSPFConfigured / isDMARCConfigured all route to the
isDNSConfigured method, which calls the Spektrum mail-server security checker
(mail_server_security_checks/tool). That tool performs a live DNS/CNAME probe of
the email domain and returns a flat dict keyed by protocol, e.g.:

    {"result": {"SPF": <bool|record-string|false>,
                "DKIM": <bool|record-string|false>,
                "DMARC": <bool|record-string|false>,
                "SMTPBanner": ...}}

DKIM/SPF/DMARC are published DNS records, so they are verified by DNS lookup
(vendor-agnostic) rather than via the Abnormal API. This transformation reads the
SPF/DKIM/DMARC values and emits the per-protocol criteria keys plus the aggregate
isDNSConfigured.
"""
import json
import ast
from datetime import datetime


def extract_input(input_data):
    enriched_validation = None
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        enriched_validation = input_data["validation"]
        input_data = input_data["data"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(4):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    if enriched_validation is not None:
        return data, enriched_validation
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
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
                "category": "emailsecurity"
            }
        }
    }


def coerce_data(value):
    """Best-effort conversion of a raw response into a dict."""
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(value)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
    return value if isinstance(value, dict) else {}


def record_present(value):
    """True if a protocol value from the DNS tool indicates a record exists.

    The tool returns either a boolean, the actual DNS record string, or a falsey
    sentinel (False / "" / "False" / "None" / "not found"). Any real record string
    or boolean True counts as configured.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lower() in ("false", "none", "null", "", "no", "0", "not found", "n/a", "no banner found"):
            return False
        return len(stripped) > 0
    return bool(value)


def get_protocol(data, name):
    """Fetch a protocol value (SPF/DKIM/DMARC) regardless of key casing."""
    if name in data:
        return data.get(name)
    lowered = {k.lower(): v for k, v in data.items() if isinstance(k, str)}
    return lowered.get(name.lower())


NOT_EVALUATED_KEYS = ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured")


def not_evaluated(reason, validation=None, transformation_errors=None):
    """An unavailable DNS helper is an API error: every key is None (Not evaluated), never False."""
    return create_response(
        result={k: None for k in NOT_EVALUATED_KEYS},
        validation=validation,
        api_errors=[reason],
        transformation_errors=transformation_errors,
        fail_reasons=[reason],
        recommendations=["Re-run once the DNS lookup service is available."],
    )


def transform(input):
    is_dmarc_configured = False
    is_dkim_configured = False
    is_spf_configured = False

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        data = coerce_data(data)

        if validation.get("status") == "failed":
            return not_evaluated("Input validation failed, so the DNS records could not be evaluated.", validation)

        if not any(get_protocol(data, n) is not None for n in ("SPF", "DKIM", "DMARC")):
            return not_evaluated(
                "The DNS lookup returned no SPF, DKIM or DMARC result (error body, outage or empty "
                "response), so the email DNS records could not be evaluated.", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        is_spf_configured = record_present(get_protocol(data, "SPF"))
        is_dkim_configured = record_present(get_protocol(data, "DKIM"))
        is_dmarc_configured = record_present(get_protocol(data, "DMARC"))

        is_dns_configured = is_dmarc_configured and is_dkim_configured and is_spf_configured

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
            fail_reasons.append("Missing DNS records: " + ", ".join(not_configured))
            recommendations.append(
                "Publish the missing DNS records (" + ", ".join(not_configured) + ") for the email domain."
            )

        for metric, configured, label in (
            ("isDMARCConfigured", is_dmarc_configured, "DMARC"),
            ("isDKIMConfigured", is_dkim_configured, "DKIM"),
            ("isSPFConfigured", is_spf_configured, "SPF"),
        ):
            if configured:
                additional_findings.append({
                    "metric": metric,
                    "status": "pass",
                    "reason": label + " record is configured"
                })
            else:
                additional_findings.append({
                    "metric": metric,
                    "status": "fail",
                    "reason": label + " DNS record not found",
                    "recommendation": "Configure " + label + " record for the email domain"
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
        return not_evaluated(
            "Transformation error: " + str(e),
            {"status": "error", "errors": [], "warnings": []},
            [str(e)],
        )
