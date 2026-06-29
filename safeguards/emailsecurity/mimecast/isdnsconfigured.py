"""
Transformation: isDNSConfigured
Vendor: Mimecast  |  Category: emailsecurity
Evaluates: Ensure that DMARC, DKIM and SPF records are set up properly.

The Mimecast workflow routes isDKIMConfigured / isSPFConfigured / isDMARCConfigured
to the isDNSConfigured method. That method calls the Spektrum mail-server security
checker (mail_server_security_checks/tool), which performs a live DNS/CNAME probe and
returns a flat dict keyed by protocol name, e.g.:

    {"SPF": <bool|record-string|false>,
     "DKIM": <bool|record-string|false>,
     "DMARC": <bool|record-string|false>,
     "Open Relay": ..., "SMTP Banner": ..., "SSL/TLS": ...}

This transformation reads the SPF/DKIM/DMARC values from that flat response and emits
the per-protocol criteria keys (isDKIMConfigured, isSPFConfigured, isDMARCConfigured)
plus the aggregate isDNSConfigured. It also tolerates Mimecast's getInternalDomain
shape ({"data": [{"dns": {"dkim": ..., "dmarc": ..., "spf": ...}}, ...]}) so the same
logic keeps working if the data source is switched to that endpoint.
"""
import json
import ast
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
                "vendor": "Mimecast",
                "category": "emailsecurity"
            }
        }
    }


def coerce_data(value):
    """Best-effort conversion of a raw response into a dict or list."""
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        for parser in (json.loads, ast.literal_eval):
            try:
                return parser(value)
            except Exception:
                pass
    return value


def record_present(value):
    """Return True if a protocol value indicates a DNS record exists.

    The DNS tool returns either a boolean, the actual DNS record string, or a falsey
    sentinel (False / "" / "False" / "None" / "not found"). A nested dict (e.g. the
    getInternalDomain dns verification object) is considered present when it reports
    valid/verified/configured or carries a record value.
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
    if isinstance(value, dict):
        for flag in ("valid", "verified", "configured", "enabled"):
            if flag in value:
                return bool(value.get(flag))
        for rec in ("record", "value", "txt"):
            if rec in value:
                return record_present(value.get(rec))
        return len(value) > 0
    return bool(value)


def protocol_from_mapping(mapping, name):
    """Fetch a protocol value (SPF/DKIM/DMARC) from a dict regardless of key casing."""
    if name in mapping:
        return mapping.get(name)
    lowered = {k.lower(): v for k, v in mapping.items() if isinstance(k, str)}
    return lowered.get(name.lower())


def evaluate_protocols(data):
    """Return (spf, dkim, dmarc) booleans from either the flat DNS-tool dict or the
    Mimecast getInternalDomain list shape."""
    if isinstance(data, dict):
        # getInternalDomain shape: {"data": [ {"dns": {...}}, ... ]}
        domains = data.get("data")
        if isinstance(domains, list) and domains:
            spf = dkim = dmarc = False
            for entry in domains:
                dns = entry.get("dns", entry) if isinstance(entry, dict) else {}
                if not isinstance(dns, dict):
                    continue
                spf = spf or record_present(protocol_from_mapping(dns, "SPF"))
                dkim = dkim or record_present(protocol_from_mapping(dns, "DKIM"))
                dmarc = dmarc or record_present(protocol_from_mapping(dns, "DMARC"))
            return spf, dkim, dmarc

        # Flat DNS-tool shape: {"SPF": ..., "DKIM": ..., "DMARC": ...}
        return (
            record_present(protocol_from_mapping(data, "SPF")),
            record_present(protocol_from_mapping(data, "DKIM")),
            record_present(protocol_from_mapping(data, "DMARC")),
        )

    return False, False, False


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
            return create_response(
                result={
                    "isDNSConfigured": False,
                    "isDMARCConfigured": False,
                    "isDKIMConfigured": False,
                    "isSPFConfigured": False
                },
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        is_spf_configured, is_dkim_configured, is_dmarc_configured = evaluate_protocols(data)

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
                "Publish the missing DNS records (" + ", ".join(not_configured) + ") for the email domain. "
                "For Mimecast-signed DKIM, ensure the Mimecast DKIM selector CNAME(s) are published."
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
        return create_response(
            result={
                "isDNSConfigured": False,
                "isDMARCConfigured": is_dmarc_configured,
                "isDKIMConfigured": is_dkim_configured,
                "isSPFConfigured": is_spf_configured
            },
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
