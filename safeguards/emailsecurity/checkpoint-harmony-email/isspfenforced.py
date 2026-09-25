"""
Transformation: isSPFEnforced
Vendor: Check Point Harmony Email & Collaboration
Method: isDNSConfigured (POST https://integrations.spektrum.ai/mail_server_security_checks/tool, the
Spektrum DNS probe of the company email domain; the same method Mimecast uses)

True when the domain's published SPF record (1) includes a Check Point sending host
(checkpoint-spf.com, the per-tenant macro include written by HEC SPF Management; or cpmails.com, the
include in Check Point's Cloud SMTP Relay guide) and (2) ends in a restrictive all-mechanism (-all or
~all). Without the include, mail Check Point relays for the domain fails SPF; with +all, ?all or no
all-mechanism, SPF does not restrict anything. No SPF record reads false.
Fails closed: an empty, error or unrecognised body proves nothing.
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

    def dns_body(data):
        """The DNS tool answers {"SPF": ..., "DKIM": ..., "DMARC": ...}, possibly wrapped in
        result / apiResponse / response. Anything without an SPF key is None."""
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
                return None
            for k in data.keys():
                if isinstance(k, str) and k.lower() == "spf":
                    return data
            nxt = None
            for key in ("result", "apiResponse", "response", "api_response", "data", "rawResponse"):
                if isinstance(data.get(key), (dict, str)):
                    nxt = data[key]
                    break
            if nxt is None:
                return None
            data = nxt
        return None

    try:
        body = dns_body(input)
        if body is None:
            return create_response(False, fail_reasons=["No DNS probe result (SPF) in the input; nothing is proven"],
                                   api_errors=["Unrecognised or error response"])
        spf = None
        for k, v in body.items():
            if isinstance(k, str) and k.lower() == "spf":
                spf = v
        record = spf.strip() if isinstance(spf, str) else ""
        if not record.lower().startswith("v=spf1"):
            return create_response(False, fail_reasons=["No SPF record is published for the email domain"],
                                   input_summary={"spfRecord": str(spf)})
        terms = record.split()
        includes = [t.split(":", 1)[1].lower() for t in terms if t.lower().startswith("include:") and ":" in t]
        cp = [d for d in includes if d.endswith("checkpoint-spf.com") or d.endswith("cpmails.com")]
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
        return create_response(False, fail_reasons=["Transformation error"], transformation_errors=[str(e)])
