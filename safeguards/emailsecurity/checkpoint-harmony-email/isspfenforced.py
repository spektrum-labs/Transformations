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

Three verdicts, never two. An empty, error or unrecognised body -- and a probe that reports
SPF as present without returning the record -- yields None with dataCollection "error", which
Token-Service grades as Unevaluated. Returning False there would have told the customer their
SPF is wrong on the strength of a response nobody could read.
"""

import json
import ast
import re
from datetime import datetime


def transform(input):
    criteriaKey = "isSPFEnforced"

    def create_response(value, pass_reasons=None, fail_reasons=None, input_summary=None,
                        api_errors=None, transformation_errors=None):
        # The status is derived from the VALUE, not from the branch that produced it.
        # None means nobody measured this, wherever in this file that happened --
        # including the except branch below, which is the one branch an author cannot
        # think about, because it is the failure of their own thinking. Setting it from
        # the value makes that branch correct without anyone deciding to make it so.
        errors = list(api_errors or [])
        if value is None and not errors:
            errors = ["isSPFEnforced was not measured from this response"]
        return {
            "transformedResponse": {criteriaKey: value},
            "additionalInfo": {
                "dataCollection": {"status": "error" if (errors or value is None) else "success",
                                   "errors": errors},
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

    def is_domain_or_subdomain(domain, base_domain):
        """Return True when domain is exactly base_domain or a subdomain of it."""
        if not isinstance(domain, str):
            return False
        d = domain.strip().strip(".").lower()
        b = base_domain.strip().strip(".").lower()
        return d == b or d.endswith("." + b)

    try:
        body = dns_body(input)
        if body is None:
            return create_response(None, fail_reasons=[],
                                   api_errors=["No DNS probe result (SPF) in the input, so SPF "
                                               "enforcement was not measured"])
        spf = None
        for k, v in body.items():
            if isinstance(k, str) and k.lower() == "spf":
                spf = v
        if spf is None or (not isinstance(spf, str) and spf):
            # The probe either said nothing about SPF, or said "yes" without returning the
            # record. Either way the all-mechanism and the includes cannot be read, so the
            # honest answer is that nothing was measured -- not that nothing is published.
            return create_response(None, fail_reasons=[],
                                   api_errors=["The DNS probe returned no SPF record text, so "
                                               "SPF enforcement was not measured"],
                                   input_summary={"spfRecord": str(spf)})
        record = spf.strip() if isinstance(spf, str) else ""
        terms = record.split()
        # RFC 7208 s4.5: the version section is exactly "v=spf1", terminated by a space or
        # the end of the record; the RFC's own example of what must be discarded is a
        # record whose version section is "v=spf10", which startswith("v=spf1") accepts.
        if not terms or terms[0].lower() != "v=spf1":
            return create_response(False, fail_reasons=["No SPF record is published for the email domain"],
                                   input_summary={"spfRecord": str(spf)})
        includes = [t.split(":", 1)[1].lower() for t in terms if t.lower().startswith("include:") and ":" in t]
        cp = [d for d in includes if is_domain_or_subdomain(d, "checkpoint-spf.com") or
              is_domain_or_subdomain(d, "cpmails.com")]
        # RFC 7208 s4.6.2: mechanisms are evaluated left to right and "if it matches,
        # processing ends and the qualifier value is returned". "all" always matches, so
        # the FIRST all-term decides and anything after it is unreachable. Reading the
        # last one passes "v=spf1 +all -all", where a receiver applies +all.
        alls = [t.lower() for t in terms if re.match(r"^[-~?+]?all$", t.lower())]
        qualifier = alls[0] if alls else ""
        restrictive = qualifier in ("-all", "~all")
        summary = {"spfRecord": record, "checkPointIncludes": cp, "allMechanism": qualifier or "none"}
        if len(alls) > 1:
            summary["unreachableAllTerms"] = alls[1:]
        if cp and restrictive:
            return create_response(True, pass_reasons=["The SPF record includes Check Point's sending hosts (" +
                                   ", ".join(cp) + ") and its first all-mechanism is " + qualifier],
                                   input_summary=summary)
        reasons = []
        if not cp:
            reasons.append("The SPF record has no Check Point include (checkpoint-spf.com or cpmails.com), so mail "
                           "Check Point sends for the domain fails SPF")
        if not restrictive:
            reasons.append("The first all-mechanism in the SPF record is " +
                           (qualifier or "absent") + ", which does not restrict unlisted senders")
        return create_response(False, fail_reasons=reasons, input_summary=summary)
    except Exception as e:
        # api_errors as well as transformation_errors: the grading path reads
        # dataCollection.status and never transformation.status, so transformation_errors
        # alone would have shipped this crash to the customer as a measured red.
        return create_response(None, fail_reasons=[], transformation_errors=[str(e)],
                               api_errors=["The DNS probe response could not be read: " + str(e)])
