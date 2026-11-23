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

A body the lookup did answer is then judged on enforcing strength, not on a non-empty record: SPF must end in -all or
~all, DMARC must request at least quarantine for the domain and its subdomains (p=reject passes at any pct; p=quarantine needs pct=100), and DKIM must publish a
key that is not revoked. The same block runs in Google, Mimecast, Check Point and Avanan.
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

# The probe answers each protocol with a bool, a record string, or false. When it
# stringifies the bool, "True" has to mean what True means -- the probe said yes without
# returning the record -- or the positive form of the same answer ships as a measured red
# while the negative form ("false", "no") is correctly read as an absence. These are
# PRESENCE, not proof: the record cannot be judged, so the verdict is None for SPF and
# DMARC and presence-only for DKIM, exactly as for the bool.
PRESENT_ONLY = ("true", "yes", "y", "present", "configured", "enabled", "found",
                "published", "ok", "pass", "passed", "1")

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

    A string answer gets the same reading as the bool it is the string form of, in both
    directions. "false" and "no" are already read as an absence; "true" and "yes" have
    to be read as presence, or a probe that stringifies its booleans turns every yes
    into a measured red while every no stays correct.
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
        if low in PRESENT_ONLY:
            return "present", ""
        # A DKIM CNAME target is a hostname built from the tenant and the domain name,
        # so the customer's own words are in it: a tenant at errorlogic.com publishes
        # selector1-errorlogic-com._domainkey.errorlogic.onmicrosoft.com, and the
        # substring test below would read that domain name as our probe failing. A
        # value that is already a selector hostname is a record, not an error. The
        # exemption is scoped to DKIM, because DKIM is the only protocol whose evidence
        # is legitimately a bare hostname.
        if name == "dkim" and dkim_selector_target(text):
            return "record", text
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


def another_protocols_record(text, own_prefix):
    """True when the text is plainly the record of a different protocol (or a DKIM key record)
    sitting under this key: the body is mis-keyed, so nothing is known, which is not the same
    as this protocol publishing nothing."""
    low = text.strip().lower()
    for prefix in RECORD_PREFIXES:
        if prefix != own_prefix and low.startswith(prefix):
            return True
    tags = dkim_tag_list(text)
    # a DMARC record that lost its v tag is also "p=...;" pairs, so only an SPF key is checked for a DKIM tag list
    return own_prefix == "v=spf1" and tags is not None and "p" in tags and "v" not in tags


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
    if another_protocols_record(text, "v=spf1"):
        return None, ["The SPF answer is the record of another protocol, so SPF was not measured"], {}
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
    if another_protocols_record(text, "v=dmarc1"):
        return None, ["The DMARC answer is the record of another protocol, so DMARC was not measured"], {}
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


def dkim_tag_list(text):
    """tag=value pairs of a DKIM key record (lowercased names), or None when the text is not a
    tag list: a segment with no equals sign, or a tag name that is not a plain word."""
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
    tags = dkim_tag_list(text)
    if tags is not None:
        # A key record is a tag list (RFC 6376 s3.6.1): p is required, v is optional and names
        # DKIM1 when present, and the tags come in any order ("k=rsa; t=s; p=..."). The record
        # of another protocol, or a list with no p tag, says nothing about a DKIM key.
        if tags.get("v", "dkim1").lower() != "dkim1" or "p" not in tags:
            return None, ["The DKIM answer is not a DKIM key record (no p tag, or a v tag naming "
                          "another protocol), so DKIM was not measured"], \
                {"dkimRecord": text, "dkimEvidence": "unreadable -- not a DKIM key record"}
        if not tags["p"].replace(" ", ""):
            return False, ["The published DKIM key is revoked: RFC 6376 s6.1.2 step 7 says an "
                           "empty p= tag means the key has been revoked and a verifier MUST treat "
                           "it as a failed signature check"], \
                {"dkimRecord": text, "dkimEvidence": "DKIM record with an empty p= tag"}
        return True, [], {"dkimRecord": text, "dkimEvidence": "DKIM record with a public key"}
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
                "vendor": "Microsoft",
                "category": "Email Security"
            }
        }
    }


RESULT_KEYS = ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured")

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
    # Microsoft 365 publishes DKIM selectors as CNAMEs, so the probe may return the selector target, not a TXT record.
    if name == "DKIM" and isinstance(value, str) and dkim_selector_target(value.strip()):
        return True
    if isinstance(value, str) and is_record_text(name, value.strip().lower()):
        if name == "DKIM":
            tags = dkim_tags(value.strip().lower())
            if tags is not None and "p" in tags and not tags["p"].replace(" ", ""):
                return False  # an empty p tag is a revoked key (RFC 6376): the record is there, no key is usable
        return True
    return None


def transform(input):
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
        body = dns_body(data)
        if body is None:
            return not_evaluated(
                validation,
                "The DNS lookup returned no SPF, DKIM or DMARC answer (error body, outage or empty response)",
                "No DNS answer was returned, so this check could not be evaluated",
                "Re-evaluate this check once the DNS lookup is available"
            )
        answers = {name: read_answer(name, get_protocol(body, name)) for name in ("SPF", "DKIM", "DMARC")}
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

        # All three answered: judge enforcing strength with the block shared by every email-authentication family.
        values, fail_reasons, unmeasured_reasons, detail, all_enforcing = email_auth_verdicts(body)
        unmeasured = unmeasured_keys(values)
        pass_reasons = []
        if all_enforcing:
            pass_reasons.append("SPF, DKIM and DMARC are all published and enforcing for the email domain")
        # fail_reasons is kept when a sibling protocol is unreadable: it is the only record of which protocol failed.
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
        message = str(e)[:200]  # the text reaches the stored result, so a long one is cut
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            "Could not evaluate the response",
            f"Transformation error: {message}",
            "Re-evaluate this check once the DNS lookup succeeds",
            transformation_errors=[message]
        )
