"""Transformation: isDNSConfigured
Vendor: Google Workspace
Method: isDNSConfigured -- the Spektrum DNS probe of the company email domain.
Serves Google - Email Security, Google - MFA and Google - Backup.

isSPFConfigured, isDMARCConfigured and isDKIMConfigured answer whether the published
records ENFORCE, not whether a string came back. The 23 requirements behind each key
ask for enforcement in their own words -- "DMARC at quarantine or reject", "set for at
least soft reject", "SPF is strictly enforced" -- and until this change a domain at
v=DMARC1;p=none with v=spf1 ?all was told both were configured.

Google recommends ~all rather than -all ("v=spf1 include:_spf.google.com ~all" is the
record in every row of its own table), which is why ~all passes here: requiring -all
would fail every tenant that followed Google's published guidance. Google publishes
DKIM as a v=DKIM1 TXT record at a selector such as google._domainkey.
"""

import json
import ast
import re
from datetime import datetime

# --- BEGIN shared email-authentication semantics -------------------------------
# Byte-identical in every transformation that answers isSPFConfigured,
# isDMARCConfigured or isDKIMConfigured. One rule, applied to each vendor's shape.
#
#   SPF    RFC 7208 s4.6.2 (the qualifiers "+" pass, "-" fail, "~" softfail,
#          "?" neutral), s4.7 (with no matching mechanism the default result is
#          neutral), s8.2 ("A 'neutral' result MUST be treated exactly like the
#          'none' result"), s8.5 (softfail: the ADMD believes the host is not
#          authorized).  Enforcing = the record ends in -all or ~all.
#   DMARC  RFC 7489 s6.3 (the "p", "sp" and "pct" tags; "v" MUST be DMARC1 or the
#          record MUST be ignored), s6.6.4 (what "pct" does to the requested
#          policy).  Enforcing = the weakest treatment a conforming receiver
#          applies is quarantine or reject -- for the organizational domain AND
#          for its subdomains.
#   DKIM   RFC 6376 s3.6.1 and s6.1.2 step 7 (an empty "p=" is a revoked key, and
#          "there is no defined semantic difference between a key that has been
#          revoked and a key record that has been removed").  DKIM has no
#          enforcement strength to read, so the bar is publication of a key that
#          is not revoked.
#
# Three verdicts, never two:
#   True   a record was read and it requests enforcement
#   False  a record was read and it does not
#   None   nothing was read, so nothing is known.  create_response turns any None
#          into dataCollection.status == "error", which Token-Service grades as
#          Unevaluated.  A None must never ship as a red check.
#
# The status is per RESPONSE, not per key: Token-Service reads
# additionalInfo.dataCollection.status once (_data_collection_failure_message in
# src/utils/evaluate/evaluate.py) and records every criterion in the response as not
# evaluated.  So one unreadable protocol withholds the grade from the other two even
# when they were measured and failing.  That is the accepted trade-off -- the other
# arrangement grades the None, which is how an unreadable probe reaches a customer as a
# measured gap, and it is the defect tools/check_none_not_evaluated.py exists to stop.
# The measured failures are not lost from the RESPONSE, only from the grade: they keep
# their evaluation.failReasons and their own additionalFindings rows.  The remedy for a
# probe that drops a protocol is to fix the probe, not to grade what it did not return.

# A probe value that NAMES AN ABSENCE is a measured absence.  A probe value that names
# a resolver failure, or says it does not know, measured nothing.  RFC 7208 s4.4 draws
# the same line: "Name Error" (RCODE 3 / NXDOMAIN) returns "none" -- the domain
# publishes no record -- while a server failure, any other RCODE, or a timeout
# terminates with "temperror", which asserts nothing about what is published.
NOT_A_RECORD = ("", "false", "none", "null", "no", "0", "not found",
                "no banner found", "no record", "not configured", "missing",
                "nxdomain", "name error", "no such domain", "does not exist")

NOT_MEASURED = ("unknown", "n/a", "na", "not available", "unavailable",
                "not applicable", "not checked", "not measured", "no answer",
                "not queried", "pending", "error", "timeout", "timed out",
                "servfail", "refused")

# Substrings that mark the probe describing its own failure rather than quoting a
# record.  Tested only on values that do not open a version section, so an SPF record
# that includes a host named "mail-error.example.com" is still read as a record.
PROBE_FAILURE = ("error", "exception", "traceback", "timeout", "timed out",
                 "servfail", "refused", "failed", "failure", "could not",
                 "cannot ", "can not ", "unable to", "no answer", "try again")

RECORD_PREFIXES = ("v=spf1", "v=dmarc1", "v=dkim1")


def opens_a_record(low):
    """True when the lowercased text opens one of the three version sections."""
    for prefix in RECORD_PREFIXES:
        if low.startswith(prefix):
            return True
    return False


def probe_failure_text(low):
    """True when the lowercased text reads as the probe's own error, not a record."""
    for marker in PROBE_FAILURE:
        if marker in low:
            return True
    return False


def dns_body(value):
    """Return the dict carrying SPF / DKIM / DMARC, or None if no layer carries one.

    The probe answers {"SPF": ..., "DKIM": ..., "DMARC": ...}, sometimes as a Python
    repr or JSON string, sometimes wrapped in result / apiResponse / response. The
    stop condition is the ABSENCE of the fields we read, not recognition of a
    particular error envelope: an envelope recogniser only matches the shapes it was
    written against, and one unexpected capital letter then reads as evidence.
    """
    for attempt in range(6):
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        if isinstance(value, str):
            parsed = None
            for parser in (json.loads, ast.literal_eval):
                try:
                    parsed = parser(value)
                    break
                except Exception:
                    parsed = None
            value = parsed
        if isinstance(value, list):
            value = value[0] if len(value) == 1 else None
            continue
        if not isinstance(value, dict):
            return None
        for key in value.keys():
            if isinstance(key, str) and key.lower() in ("spf", "dkim", "dmarc"):
                return value
        nxt = None
        for key in ("data", "result", "apiResponse", "api_response", "response",
                    "Output", "output", "rawResponse", "records"):
            if key in value and isinstance(value.get(key), (dict, str, bytes, list)):
                nxt = value[key]
                break
        if nxt is None:
            return None
        value = nxt
    return None


def protocol_value(body, name):
    """(found, value) for one protocol key, case-insensitively."""
    for key in body.keys():
        if isinstance(key, str) and key.lower() == name:
            return True, body[key]
    return False, None


def record_text(body, name):
    """Reduce one probe value to a kind and, where there is one, the record text.

    "unknown"  the probe said nothing, or said it could not tell -> not measured
    "missing"  the probe looked and found no record        -> measured, absent
    "present"  the probe said yes without the record text  -> presence only
    "record"   the probe returned the published record     -> judge the text

    "unknown" and "could not resolve" are not "no record is published". Scoring them
    as an absence writes a real gap out of nothing, which is the same defect in the
    other direction as scoring a non-empty string as proof.
    """
    found, value = protocol_value(body, name)
    if not found or value is None:
        return "unknown", ""
    if isinstance(value, bool):
        return ("present", "") if value else ("missing", "")
    if isinstance(value, bytes):
        value = value.decode("utf-8", "ignore")
    if isinstance(value, str):
        text = value.strip()
        low = text.lower()
        if low in NOT_A_RECORD:
            return "missing", ""
        if low in NOT_MEASURED:
            return "unknown", ""
        if not opens_a_record(low) and probe_failure_text(low):
            return "unknown", ""
        return "record", text
    if isinstance(value, (int, float)):
        return ("present", "") if value else ("missing", "")
    if isinstance(value, (dict, list)):
        return ("present", "") if value else ("missing", "")
    return "unknown", ""


def tag_map(text, separator):
    """name=value pairs, lowercased names, first occurrence wins. Also returns the
    order, because RFC 7489 s6.3 requires "v" to be the first DMARC tag."""
    tags = {}
    order = []
    for part in text.split(separator):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip().lower()
        if name and name not in tags:
            tags[name] = value.strip()
            order.append(name)
    return tags, order


def spf_verdict(body):
    """isSPFConfigured: (verdict, reasons, detail). RFC 7208."""
    kind, text = record_text(body, "spf")
    if kind == "unknown":
        return None, ["The DNS probe returned no SPF answer, so SPF was not measured"], {}
    if kind == "present":
        return None, ["The DNS probe reported SPF as present without returning the record, so "
                      "its all-mechanism cannot be read and enforcement was not measured"], {}
    if kind == "missing":
        return False, ["No SPF record is published for the email domain"], {"spfRecord": "none"}
    # RFC 7208 s4.5: the version section is "v=spf1" terminated by a space or the end of
    # the record, and a record whose version section is "v=spf10" "does not match and is
    # discarded". startswith("v=spf1") accepts v=spf10, which the RFC names as the
    # example of what must not be accepted.
    terms = text.split()
    if not terms or terms[0].lower() != "v=spf1":
        return False, ["The TXT record found does not begin with a version section of exactly "
                       "v=spf1, so RFC 7208 s4.5 discards it and the domain publishes no SPF "
                       "record"], {"spfRecord": text}
    # RFC 7208 s4.6.2: mechanisms are evaluated left to right and "if it matches,
    # processing ends and the qualifier value is returned". "all" always matches, so the
    # FIRST all-term decides and every term after it is unreachable. Reading the last one
    # passes "v=spf1 +all -all", where a receiver applies +all.
    alls = [t.lower() for t in terms if re.match(r"^[-~?+]?all$", t.lower())]
    qualifier = alls[0] if alls else ""
    detail = {"spfRecord": text,
              "spfAllMechanism": qualifier if qualifier else "none",
              "spfHardFail": qualifier == "-all"}
    if len(alls) > 1:
        detail["spfUnreachableAllTerms"] = alls[1:]
    if not qualifier:
        redirects = [t for t in terms if t.lower().startswith("redirect=")]
        if redirects:
            detail["spfRedirect"] = redirects[0]
            return None, ["The SPF record carries " + redirects[0] + " and has no all-mechanism "
                          "of its own; RFC 7208 s6.1 puts the effective policy in the redirected "
                          "record, which this probe does not resolve, so enforcement was not "
                          "measured"], detail
        return False, ["The SPF record publishes no all-mechanism, so RFC 7208 s4.7 makes its "
                       "default result neutral and it restricts no sender"], detail
    if qualifier in ("-all", "~all"):
        return True, [], detail
    if qualifier == "?all":
        return False, ["The first all-mechanism in the SPF record is ?all (neutral), which RFC "
                       "7208 s8.2 requires be treated exactly like publishing no SPF record at "
                       "all"], detail
    return False, ["The first all-mechanism in the SPF record is " + qualifier + ", which "
                   "authorises every host on the internet to send as this domain"], detail


def dmarc_pct(tags):
    """RFC 7489 s6.4: pct is an integer 0-100, default 100. A malformed value is not a
    smaller percentage, so it is ignored rather than guessed at."""
    raw = tags.get("pct", "").strip()
    if raw and re.match(r"^[0-9]{1,3}$", raw):
        number = int(raw)
        if number <= 100:
            return number
    return 100


def dmarc_floor(policy, pct):
    """The weakest treatment a conforming receiver applies, per RFC 7489 s6.6.4.

    With pct < 100 the receiver MUST NOT enact the requested policy on more than that
    percentage. Mail outside the sample is treated as quarantine when the request was
    reject, and gets "local message classification as normal" -- which is none -- when
    the request was quarantine. So pct weakens quarantine to nothing and weakens reject
    only as far as quarantine.
    """
    if policy == "reject":
        return "reject" if pct >= 100 else "quarantine"
    if policy == "quarantine":
        return "quarantine" if pct >= 100 else "none"
    return "none"


def dmarc_verdict(body):
    """isDMARCConfigured: (verdict, reasons, detail). RFC 7489."""
    kind, text = record_text(body, "dmarc")
    if kind == "unknown":
        return None, ["The DNS probe returned no DMARC answer, so DMARC was not measured"], {}
    if kind == "present":
        return None, ["The DNS probe reported DMARC as present without returning the record, so "
                      "its p= policy cannot be read and enforcement was not measured"], {}
    if kind == "missing":
        return False, ["No DMARC record is published for the email domain"], {"dmarcRecord": "none"}
    tags, order = tag_map(text, ";")
    if tags.get("v", "").lower() != "dmarc1":
        return False, ["The TXT record found carries no v=DMARC1 tag; RFC 7489 s6.3 requires the "
                       "entire record be ignored without it"], {"dmarcRecord": text}
    policy = tags.get("p", "").strip().lower()
    if policy not in ("none", "quarantine", "reject"):
        return False, ["The DMARC record requests no recognised policy (p=" +
                       (policy if policy else "absent") + "); RFC 7489 s6.3 makes p mandatory for "
                       "a policy record and defines only none, quarantine and reject"],             {"dmarcRecord": text, "dmarcPolicy": policy if policy else "absent"}
    pct = dmarc_pct(tags)
    org_floor = dmarc_floor(policy, pct)
    sub_policy = tags.get("sp", "").strip().lower()
    if sub_policy in ("none", "quarantine", "reject"):
        sub_floor = dmarc_floor(sub_policy, pct)
    else:
        sub_policy = ""
        sub_floor = org_floor
    detail = {"dmarcRecord": text,
              "dmarcPolicy": policy,
              "dmarcPct": pct,
              "dmarcSubdomainPolicy": sub_policy if sub_policy else "inherits p",
              "dmarcEffectivePolicy": org_floor,
              "dmarcEffectiveSubdomainPolicy": sub_floor,
              "dmarcVersionTagFirst": bool(order) and order[0] == "v"}
    reasons = []
    if org_floor not in ("quarantine", "reject"):
        if policy == "none":
            reasons.append("The DMARC record is p=none, which RFC 7489 s6.3 defines as requesting "
                           "no specific action: it monitors spoofing and prevents none of it")
        else:
            reasons.append("The DMARC record is p=" + policy + " with pct=" + str(pct) +
                           ", so under RFC 7489 s6.6.4 the other " + str(100 - pct) +
                           "% of failing mail gets normal local classification")
    if sub_floor not in ("quarantine", "reject"):
        reasons.append("The DMARC record sets sp=" + (sub_policy if sub_policy else "none") +
                       ", so every subdomain of the email domain is left unenforced (RFC 7489 "
                       "s6.3: sp applies to all subdomains in place of p)")
    if reasons:
        return False, reasons, detail
    return True, [], detail


DKIM_SELECTOR_SUFFIXES = (".onmicrosoft.com", ".dkim.mail.microsoft", ".mimecast.com",
                          ".dkim.amazonses.com", ".dkim.mailchannels.net")


def dkim_selector_target(text):
    """True when the text is the HOSTNAME a DKIM CNAME selector points at.

    Microsoft 365, Mimecast and Amazon SES publish DKIM as a CNAME, so the probe sees a
    target hostname and no v=DKIM1 tag. That is the only reason a value without the tag
    may count as published. The test must be for a hostname, not for "not in the
    stop-list": every error string the probe has not been taught to name would otherwise
    read as a selector. A hostname is one token with a dot in it and no tag punctuation,
    and it names the _domainkey subtree the selector lives in (RFC 6376 s3.6.1).
    """
    if not text:
        return False
    if len(text.split()) != 1:
        return False
    low = text.lower().strip(".")
    for punctuation in ("=", ";", ":", "/", ",", '"'):
        if punctuation in low:
            return False
    if "." not in low:
        return False
    if "._domainkey" in low:
        return True
    for suffix in DKIM_SELECTOR_SUFFIXES:
        if low.endswith(suffix):
            return True
    return False


def dkim_verdict(body):
    """isDKIMConfigured: (verdict, reasons, detail). RFC 6376.

    DKIM publishes no enforcement strength -- there is no DKIM equivalent of p= or
    -all -- so the bar is a published selector whose key has not been revoked.
    """
    kind, text = record_text(body, "dkim")
    if kind == "unknown":
        return None, ["The DNS probe returned no DKIM answer, so DKIM was not measured"], {}
    if kind == "missing":
        return False, ["No DKIM selector record is published for the email domain, so outbound "
                       "mail carries no verifiable signature"], {"dkimRecord": "none"}
    if kind == "present":
        return True, [], {"dkimRecord": "present",
                          "dkimEvidence": "the probe reported a selector without returning the "
                                          "record, so the key could not be checked for revocation"}
    if "v=dkim1" in text.lower():
        tags, order = tag_map(text, ";")
        if not tags.get("p", "").strip():
            return False, ["The published DKIM key is revoked: RFC 6376 s6.1.2 step 7 says an "
                           "empty p= tag means the key has been revoked and a verifier MUST treat "
                           "it as a failed signature check"],                 {"dkimRecord": text, "dkimEvidence": "v=DKIM1 record with an empty p= tag"}
        return True, [], {"dkimRecord": text,
                          "dkimEvidence": "v=DKIM1 record with a public key"}
    if dkim_selector_target(text):
        return True, [], {"dkimRecord": text,
                          "dkimEvidence": "presence only -- the probe returned a selector target "
                                          "rather than a v=DKIM1 TXT record, which is what "
                                          "Microsoft 365's CNAME selector model publishes"}
    return None, ["The DKIM answer is neither a v=DKIM1 record nor a selector hostname, so it "
                  "carries no evidence either way and DKIM was not measured"],         {"dkimRecord": text,
         "dkimEvidence": "unreadable -- not a v=DKIM1 record and not a _domainkey target"}


def email_auth_verdicts(body):
    """The four criteria, their reasons, the evidence, and the composite verdict.

    The reasons come back in two lists, because they answer two different questions. A
    reason belonging to a criterion that was MEASURED and failed is a finding and keeps
    its place in evaluation.failReasons even when a sibling protocol was unreadable --
    an unreadable DKIM withholds the grade (see the note on the status above) but must
    not also erase the sentence explaining why SPF failed. A reason belonging to a
    criterion that was NOT measured is not a finding; it goes to dataCollection.errors,
    which is where "we could not read this" belongs.
    """
    spf, spf_reasons, spf_detail = spf_verdict(body)
    dmarc, dmarc_reasons, dmarc_detail = dmarc_verdict(body)
    dkim, dkim_reasons, dkim_detail = dkim_verdict(body)
    parts = [spf, dmarc, dkim]
    if None in parts:
        dns = None
    else:
        dns = bool(spf and dmarc and dkim)
    values = {"isDNSConfigured": dns,
              "isDMARCConfigured": dmarc,
              "isDKIMConfigured": dkim,
              "isSPFConfigured": spf}
    detail = {}
    for part in (spf_detail, dmarc_detail, dkim_detail):
        for key in part.keys():
            detail[key] = part[key]
    fail_reasons = []
    unmeasured_reasons = []
    for verdict, reasons in ((spf, spf_reasons), (dmarc, dmarc_reasons), (dkim, dkim_reasons)):
        if verdict is None:
            unmeasured_reasons = unmeasured_reasons + reasons
        elif not verdict:
            fail_reasons = fail_reasons + reasons
    # `dns` is handed back separately rather than read out of `values` by name: a
    # transform that reads a criteria key out of input-derived data is the self-answer
    # defect, and tools/check_no_self_answer.py cannot tell our own dict from the
    # vendor's. Keeping the local is simpler than arguing about it.
    return values, fail_reasons, unmeasured_reasons, detail, dns


def unmeasured_keys(values):
    """The criteria this body could not answer. The status is derived from this and
    from nothing else, so a branch nobody thought about still reports honestly."""
    return sorted([key for key in values.keys() if values[key] is None])
# --- END shared email-authentication semantics ---------------------------------


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    """dataCollection.status is derived from the VALUES, never from the branch.

    A criterion left as None is a criterion nobody measured, wherever in this file that
    happened -- including the except branch, which is the one branch an author cannot
    think about, because it is the failure of their own thinking. Deriving the status
    from the value is what makes that branch correct without anyone deciding to make it
    correct. Do not replace this with a list of key names: Rubrik protected its numeric
    keys with exactly such a list and missed complianceStatus because the name ends in
    "Status". A value-keyed rule cannot miss a key.
    """
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    errors = list(api_errors or [])
    unmeasured = unmeasured_keys(result) if isinstance(result, dict) else []
    if unmeasured and not errors:
        errors = ["not measured from this response: " + ", ".join(unmeasured)]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (errors or unmeasured) else "success",
                "errors": errors
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
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


ALL_NONE = {"isDNSConfigured": None, "isDMARCConfigured": None,
            "isDKIMConfigured": None, "isSPFConfigured": None}

LABELS = (("isDMARCConfigured", "DMARC", "Publish a DMARC record at p=quarantine or p=reject "
                                         "(pct=100) for the email domain and every subdomain "
                                         "that sends mail"),
          ("isDKIMConfigured", "DKIM", "Publish a DKIM selector for the email domain and enable "
                                       "signing of outbound mail"),
          ("isSPFConfigured", "SPF", "Publish an SPF record listing every authorised sender and "
                                     "ending in -all (or ~all)"))


def findings_for(values, reasons, detail):
    """One additionalFindings row per criterion, carrying the record that decided it."""
    rows = []
    for key, label, advice in LABELS:
        value = values.get(key)
        if value is None:
            rows.append({"metric": key, "status": "notMeasured",
                         "reason": label + " could not be read from this response"})
        elif value:
            rows.append({"metric": key, "status": "pass",
                         "reason": label + " is published and enforcing"})
        else:
            rows.append({"metric": key, "status": "fail",
                         "reason": label + " does not meet the enforcing bar",
                         "recommendation": advice})
    rows.append({"metric": "evidence", "status": "info", "reason": "records read",
                 "detail": detail})
    return rows


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    return input_data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def transform(input):
    try:
        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result=dict(ALL_NONE),
                validation=validation,
                api_errors=["input validation failed, so no DNS record was read"]
            )

        body = dns_body(data)
        if body is None:
            return create_response(
                result=dict(ALL_NONE),
                validation=validation,
                api_errors=["the response carries no SPF, DKIM or DMARC answer, so no email "
                            "authentication record was read"]
            )

        values, fail_reasons, unmeasured_reasons, detail, all_enforcing = \
            email_auth_verdicts(body)
        unmeasured = unmeasured_keys(values)
        pass_reasons = []
        if all_enforcing:
            pass_reasons.append("SPF, DKIM and DMARC are all published and enforcing for the "
                                "email domain")
        # fail_reasons is NOT emptied when a sibling protocol is unreadable. The grade is
        # withheld for the whole response either way, because the status is per response;
        # dropping the sentences as well would throw away the only record of which
        # protocol failed and why, in exactly the response a human has to read to find out.
        return create_response(
            result=values,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=[],
            additional_findings=findings_for(values, fail_reasons, detail),
            input_summary=detail,
            api_errors=([("these criteria were not measured: " + ", ".join(unmeasured)) + "; " +
                         " ".join(unmeasured_reasons)] if unmeasured else None)
        )

    except Exception as e:
        # Every criterion is None, so create_response derives dataCollection "error"
        # whatever this branch remembers to pass. api_errors is given as well, because
        # transformation_errors alone lands under transformation.status, which the
        # grading path never reads.
        return create_response(
            result=dict(ALL_NONE),
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=["the DNS probe response could not be read: " + str(e)],
            fail_reasons=[]
        )
