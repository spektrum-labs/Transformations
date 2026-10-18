"""
Transformation: isSPFEnforced
Vendor: Check Point Harmony Email & Collaboration
Method: isDNSConfigured (the mail_server_security_checks/tool method, the
Spektrum DNS probe of the company email domain; the same method Mimecast uses)

True when the domain's published SPF record (1) includes a Check Point sending host
(checkpoint-spf.com, the per-tenant macro include written by HEC SPF Management; or cpmails.com, the
include in Check Point's Cloud SMTP Relay guide) and (2) ends in a restrictive all-mechanism (-all or
~all). Without the include, mail Check Point relays for the domain fails SPF; with +all, ?all or no
all-mechanism, SPF does not restrict anything. A probe that answers "no SPF record" (false, null, an
empty string or a marker such as None or not found) reads false: that is a readable answer.
Not evaluated (None, with a data-collection error) when the body is an error, empty or unrecognised, or
when the SPF value is neither a record nor a "no record" marker, or when the answer or a wrapper around it
carries an error marker (error, errors, or an HTTP status of 400 or more in status, statusCode or
status_code, as a number or as text): it proves nothing, so it is never False.
"""

import json
import ast
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isSPFEnforced"

    def create_response(value, pass_reasons=None, fail_reasons=None, input_summary=None,
                        api_errors=None, transformation_errors=None):
        return {
            "transformedResponse": {criteriaKey: value},
            "additionalInfo": {
                "dataCollection": {"status": "error" if api_errors else "success",
                                   "errors": api_errors or []},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "error" if transformation_errors else "success",
                                   "errors": transformation_errors or [],
                                   "inputSummary": input_summary or {}},
                "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                               "recommendations": [], "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z",
                             "schemaVersion": "1.0", "transformationId": criteriaKey,
                             "vendor": "Check Point Harmony Email & Collaboration",
                             "method": "isDNSConfigured"},
            },
        }

    def not_measured(reason, transformation_errors=None):
        """No verdict: the value is None and dataCollection.status is "error", so the evaluator
        shows Not evaluated instead of a failed check. The reason is fixed text; exception text
        goes under transformation errors only."""
        return create_response(None, fail_reasons=[reason], api_errors=[reason],
                               transformation_errors=transformation_errors)

    def http_status(value):
        """An HTTP status as a number: a number, or text such as "401" or " 403 ". Booleans, blank
        or non-numeric text and any other type are None, which is not an error."""
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            digits = value.strip()
            if digits.isascii() and digits.isdigit():
                return int(digits)
        return None

    def marker_error(obj):
        """Fixed reason when this one object says the call failed (error, errors, or an HTTP
        status of 400 or more in status, statusCode or status_code), else None. The probe's own
        text is never copied into the reason."""
        if obj.get("error") or obj.get("errors"):
            return "The DNS probe answered with an error; nothing is measured."
        for field in ("status", "statusCode", "status_code"):
            code = http_status(obj.get(field))
            if code is not None and code >= 400:
                return "The DNS probe answered with an HTTP error; nothing is measured."
        return None

    def dns_body(data):
        """The DNS tool answers {"SPF": ..., "DKIM": ..., "DMARC": ...}, possibly wrapped in
        result / apiResponse / response. Returns (body, error): body is None when no SPF key is
        found; error is a fixed reason when the answer or a wrapper around it carries an error
        marker, in which case nothing inside it is trusted."""
        for attempt in range(5):
            if isinstance(data, bytes):
                data = data.decode("utf-8")
            if isinstance(data, str):
                parsed = None
                for parser in (json.loads, ast.literal_eval):
                    try:
                        parsed = parser(data)
                        break
                    except Exception:
                        parsed = None
                data = parsed
            if not isinstance(data, dict):
                return None, None
            err = marker_error(data)
            if err:
                return None, err
            for k in data.keys():
                if isinstance(k, str) and k.lower() == "spf":
                    return data, None
            nxt = None
            for key in ("result", "apiResponse", "response", "api_response", "data", "rawResponse"):
                if isinstance(data.get(key), (dict, str)):
                    nxt = data[key]
                    break
            if nxt is None:
                return None, None
            data = nxt
        return None, None

    def is_domain_or_subdomain(domain, base_domain):
        """Return True when domain is exactly base_domain or a subdomain of it."""
        if not isinstance(domain, str):
            return False
        d = domain.strip().strip(".").lower()
        b = base_domain.strip().strip(".").lower()
        return d == b or d.endswith("." + b)

    try:
        body, err = dns_body(input)
        if err:
            return not_measured(err)
        if body is None:
            return not_measured("No readable DNS probe result (SPF) in the input; nothing is measured.")
        spf = None
        for k, v in body.items():
            if isinstance(k, str) and k.lower() == "spf":
                spf = v
        record = spf.strip() if isinstance(spf, str) else ""
        no_record_markers = ("", "false", "none", "null", "no", "0", "not found", "n/a")
        if spf is None or spf is False or (isinstance(spf, str) and record.lower() in no_record_markers):
            return create_response(False, fail_reasons=["No SPF record is published for the email domain"],
                                   input_summary={"spfRecord": str(spf)})
        if not record.lower().startswith("v=spf1"):
            return not_measured("The DNS probe returned an SPF value that is not an SPF record; nothing is measured.")
        terms = record.split()
        includes = [t.split(":", 1)[1].lower() for t in terms if t.lower().startswith("include:") and ":" in t]
        cp = [d for d in includes if is_domain_or_subdomain(d, "checkpoint-spf.com") or
              is_domain_or_subdomain(d, "cpmails.com")]
        alls = [t.lower() for t in terms if re.match(r"^[-~?+]?all$", t.lower())]
        qualifier = alls[-1] if alls else ""
        restrictive = qualifier in ("-all", "~all")
        summary = {"spfRecord": record, "checkPointIncludes": cp, "allMechanism": qualifier or "none"}
        if cp and restrictive:
            return create_response(True, pass_reasons=["The SPF record includes Check Point's sending hosts (" +
                                   ", ".join(cp) + ") and ends in " + qualifier], input_summary=summary)
        reasons = []
        if not cp:
            reasons.append("The SPF record has no Check Point include (checkpoint-spf.com or cpmails.com), so mail "
                           "Check Point sends for the domain fails SPF")
        if not restrictive:
            reasons.append("The SPF record ends in " + (qualifier or "no all-mechanism") +
                           ", which does not restrict unlisted senders")
        return create_response(False, fail_reasons=reasons, input_summary=summary)
    except Exception as e:
        return not_measured("The response could not be processed; nothing is measured.",
                            transformation_errors=[str(e)])
