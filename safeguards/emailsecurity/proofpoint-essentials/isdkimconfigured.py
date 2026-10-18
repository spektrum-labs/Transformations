"""
Transformation: isDKIMConfigured
Vendor: Proofpoint  |  Product: Proofpoint Essentials  |  Category: Email Security

Integration-Service workflow getDkimPosture:
  GET /api/v1/me                         (who the login is: organization or partner admin)
  GET /api/v1/orgs/{domain}              (active, package, licences, domains)
  GET /api/v1/orgs/{domain}/domains/{targetDomain}/dkim  (one call per organization domain)
  API guide: https://us1.proofpointessentials.com/api/v1/docs/index.php
  API specification: https://us1.proofpointessentials.com/api/v1/docs/specification.php

True when the organization's primary domain has a DKIM signing key in Proofpoint Essentials
that passed validation (is_valid), and no domain has keys of which none is valid. False when
the primary domain has no valid key while Essentials signs for the organization, or a domain's
keys all fail validation. Null when Essentials holds no DKIM key for any domain: outbound mail
may be signed by the mail platform, which this integration cannot see. SPF and DMARC are not
in the Essentials API and are not judged here.

Fail closed: an error, 401/403, empty or unrecognised read, a partner login, or a login for a
different organization is null with dataCollection status "error" (Not evaluated), never a pass.
"""

import json
from datetime import datetime, timezone

VENDOR = "Proofpoint"
PRODUCT = "Proofpoint Essentials"
CATEGORY = "Email Security"
LEG_KEYS = ("me", "organization", "features", "licensing", "inboundReport", "emailTagging", "dkim")
PARTNER_ENTITY_TYPES = ("oem_partner", "strategic_partner", "channel")
PARTNER_USER_TYPES = ("oem_partner_admin", "strategic_partner_admin", "channel_admin")
PACKAGES = ("beginner", "business", "business_plus", "advanced", "advanced_plus", "professional",
            "professional_plus")
# Which licensing packages include a feature: the Features table of the Proofpoint Essentials
# API guide (https://us1.proofpointessentials.com/api/v1/docs/index.php#features).
FEATURE_PACKAGES = {
    "attachment_defense": ("business", "business_plus", "advanced", "advanced_plus", "professional",
                           "professional_plus"),
    "attachment_defense_sandboxing": ("advanced", "advanced_plus", "professional", "professional_plus"),
    "url_defense": ("business", "business_plus", "advanced", "advanced_plus", "professional",
                    "professional_plus"),
    "anti_spoofing": PACKAGES,
    "email_warning_tags": ("advanced_plus", "professional_plus"),
    "automatic_remediation": ("advanced_plus", "professional_plus"),
}
WRAPPERS = ("data", "response", "result", "apiResponse", "Output")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def find_legs(data):
    """The merged workflow output: a dict carrying the workflow's leg keys, possibly under the
    usual Integration-Service wrappers."""
    for depth in range(6):
        if not isinstance(data, dict):
            return None
        for key in LEG_KEYS:
            if key in data:
                return data
        nxt = None
        for key in WRAPPERS:
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def as_int(value):
    """A count, from a number or a digit string (stored responses carry every leaf as a string)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def flag(value):
    """True / False from a boolean or its documented string forms; None for anything else.
    The Essentials features resource says its values are strings "to allow for multiple data
    types", so "false" must read as off, never as a non-empty (truthy) string."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value in (0, 1):
            return value == 1
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "1", "yes", "on", "enabled"):
            return True
        if text in ("false", "0", "no", "off", "disabled"):
            return False
    return None


def error_text(body):
    """Why a leg body is an error, or None. Integration-Service error envelopes, HTTP status
    envelopes (401 and 403 included) and Proofpoint error bodies all count."""
    if body is None:
        return "not returned"
    if not isinstance(body, dict):
        return "not an object"
    if body.get("error") is True or body.get("errorType"):
        return ("Integration-Service error " + str(body.get("statusCode") or "") + ": " +
                str(body.get("message") or body.get("errorMessage") or "")[:200]).strip()
    for key in ("statusCode", "status_code", "status"):
        code = as_int(body.get(key))
        if code is not None and code >= 400:
            return "HTTP " + str(code)
    if str(body.get("status") or "").lower() == "error":
        return "error: " + str(body.get("message") or "")[:200]
    if body.get("error_message") or isinstance(body.get("errors"), list) or isinstance(body.get("error"), str):
        return "Proofpoint error: " + str(body.get("error_message") or body.get("error") or body.get("errors"))[:200]
    return None


def read_leg(legs, key, label):
    """(body, problem) for one leg that must be a readable object."""
    if key not in legs:
        return None, label + ": not returned"
    body = legs.get(key)
    problem = error_text(body)
    if problem:
        return None, label + ": " + problem
    if not body:
        return None, label + ": empty response"
    return body, None


def read_identity(legs):
    """(me, organization, problem). Refuses a partner login and a login for a different
    organization: their reads would describe an organization other than the customer's."""
    me, problem = read_leg(legs, "me", "GET /me")
    if problem:
        return None, None, problem
    org, problem = read_leg(legs, "organization", "GET /orgs/{domain}")
    if problem:
        return None, None, problem
    entity_type = str(me.get("entity_type") or "").lower()
    user_type = str(me.get("type") or "").lower()
    if (flag(me.get("is_partner_admin")) is True or entity_type in PARTNER_ENTITY_TYPES
            or user_type in PARTNER_USER_TYPES):
        return None, None, ("the connected login is a partner administrator (" + (user_type or entity_type) +
                            "), which can reach every organization under the partner; connect with an "
                            "Organization Admin of this organization instead")
    if entity_type != "organization":
        return None, None, "GET /me did not say which organization the login belongs to"
    me_domain = str(me.get("entity_primary_domain") or "").strip().lower()
    org_domain = str(org.get("primary_domain") or "").strip().lower()
    if not me_domain or not org_domain:
        return None, None, "the organization's primary domain was not returned"
    if me_domain != org_domain:
        return None, None, ("the connected login belongs to " + me_domain + ", not to " + org_domain +
                            "; connect with an Organization Admin of " + org_domain)
    org_type = str(org.get("type") or "organization").lower()
    if org_type != "organization":
        return None, None, "the configured domain is a partner account (" + org_type + "), not an organization"
    return me, org, None


def org_findings(org):
    domains = [d for d in (org.get("domains") or []) if isinstance(d, dict) and d.get("name")]
    relay = [d for d in domains if flag(d.get("is_relay")) is True and flag(d.get("is_active")) is True]
    out = []
    if org.get("licensing_package"):
        out.append("Licensing package: " + str(org.get("licensing_package")))
    if as_int(org.get("user_licenses")) is not None:
        out.append("Licensed users: " + str(as_int(org.get("user_licenses"))))
    if as_int(org.get("active_users")) is not None:
        out.append("Active users: " + str(as_int(org.get("active_users"))))
    out.append("Domains: " + str(len(domains)) + " (" + str(len(relay)) + " active relay)")
    if org.get("deployment_method"):
        out.append("Deployment method: " + str(org.get("deployment_method")))
    return out


def feature_state(features, org, name, label):
    """(state, detail) for one Essentials feature flag. A feature missing from the response is
    off only when the organization's package does not include it; otherwise it was not read."""
    if name in features:
        state = flag(features.get(name))
        if state is None:
            return None, label + " (" + name + ") has an unrecognised value: " + str(features.get(name))[:40]
        return state, label + " (" + name + ") is " + ("enabled" if state else "disabled")
    package = str(org.get("licensing_package") or "").strip().lower()
    if package in PACKAGES and package not in FEATURE_PACKAGES.get(name, PACKAGES):
        return False, (label + " is not part of the organization's " + package +
                       " package, so it is not enabled")
    return None, label + " (" + name + ") was not in the features response"


def org_active(org):
    """True / False / None: is the organization active in Proofpoint Essentials."""
    return flag(org.get("is_active"))


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id="", findings=None):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "product": PRODUCT,
                         "category": CATEGORY},
        },
    }


def not_evaluated(key, transform_id, problem, summary=None):
    return build_response({key: None}, errors=[problem], summary=summary, transform_id=transform_id)


def load(input):
    """(legs, me, org, problem) for the workflow output."""
    legs = find_legs(parse(input))
    if legs is None:
        return None, None, None, "no Proofpoint Essentials workflow output in the response"
    me, org, problem = read_identity(legs)
    return legs, me, org, problem

CRITERIA_KEY = "isDKIMConfigured"
TRANSFORM_ID = "isdkimconfigured"
MAX_DOMAINS = 100
MAX_NAMED = 10


def keypairs_of(body):
    """(keypairs, problem) for one domain's DKIM response: a list, or a list under a wrapper."""
    if isinstance(body, list):
        return [k for k in body if isinstance(k, dict)], None
    if isinstance(body, dict):
        problem = error_text(body)
        if problem:
            return None, problem
        for key in ("apiResponse", "data", "dkim", "keypairs", "result", "response"):
            if isinstance(body.get(key), list):
                return [k for k in body[key] if isinstance(k, dict)], None
    return None, "unrecognised DKIM response"


def named(items):
    shown = items[:MAX_NAMED]
    more = len(items) - len(shown)
    return ", ".join(shown) + (" and " + str(more) + " more" if more > 0 else "")


def transform(input):
    try:
        legs, me, org, problem = load(input)
        if problem:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, problem)
        domains = org.get("domains")
        if not isinstance(domains, list):
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "the organization's domains were not returned")
        names = [str(d.get("name")).strip().lower() for d in domains if isinstance(d, dict) and d.get("name")]
        if not names or len(names) != len(domains):
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "the organization's domain list is empty or unreadable")
        stats = legs.get("iterateStats") if isinstance(legs.get("iterateStats"), dict) else {}
        dkim_stats = stats.get("dkim") if isinstance(stats.get("dkim"), dict) else {}
        if legs.get("iterateTruncated") is True or dkim_stats.get("iterateTruncated") is True or len(names) > MAX_DOMAINS:
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "more than " + str(MAX_DOMAINS) + " domains; not every domain's DKIM keys were read")
        leg = legs.get("dkim")
        if isinstance(leg, dict):
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET .../dkim: " + (error_text(leg) or "one object where one response per domain was expected"))
        if not isinstance(leg, list):
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET .../dkim: not returned")
        if len(leg) != len(names):
            return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, str(len(leg)) + " DKIM responses for " + str(len(names)) + " domains")
        valid, invalid, unsigned = [], [], []
        for index in range(len(names)):
            domain = names[index]
            keys, problem = keypairs_of(leg[index])
            if problem:
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "GET /orgs/{domain}/domains/" + domain + "/dkim: " + problem)
            for key in keys:
                owner = str(key.get("domain") or domain).strip().lower()
                if owner != domain:
                    return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "DKIM responses are not aligned with the domain list")
            states = [flag(key.get("is_valid")) for key in keys]
            if not keys:
                unsigned.append(domain)
            elif True in states:
                valid.append(domain)
            elif None in states:
                return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "DKIM key validation state not returned for " + domain)
            else:
                invalid.append(domain)
        primary = str(org.get("primary_domain") or "").strip().lower()
        summary = {"domains": len(names), "validDomains": valid, "invalidDomains": invalid, "unsignedDomains": unsigned,
                   "primaryDomain": primary}
        result = {CRITERIA_KEY: None, "domainsWithValidKey": len(valid), "domainsWithOnlyInvalidKeys": len(invalid),
                  "domainsWithoutKey": len(unsigned)}
        findings = org_findings(org)
        if unsigned:
            findings.append("Domains with no Proofpoint Essentials DKIM key: " + named(unsigned))
        if not valid and not invalid:
            return build_response(result, errors=[
                "Proofpoint Essentials holds no DKIM signing key for any of the organization's domains; outbound "
                "mail may be signed by the mail platform, which this integration cannot see"],
                summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        if invalid:
            result[CRITERIA_KEY] = False
            return build_response(result, fail_reasons=["DKIM keys in Proofpoint Essentials fail validation for: " + named(invalid)],
                                  recommendations=["Publish the DKIM public key in DNS for each domain and verify it in Proofpoint Essentials"],
                                  summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        if primary not in valid:
            result[CRITERIA_KEY] = False
            return build_response(result, fail_reasons=[
                "The primary domain " + primary + " has no valid DKIM signing key in Proofpoint Essentials (valid keys: " +
                named(valid) + ")"],
                recommendations=["Create and verify a DKIM key for the primary domain in Proofpoint Essentials"],
                summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        result[CRITERIA_KEY] = True
        return build_response(result, pass_reasons=["Valid Proofpoint Essentials DKIM signing keys for: " + named(valid)],
                              summary=summary, transform_id=TRANSFORM_ID, findings=findings)
    except Exception as error:
        return not_evaluated(CRITERIA_KEY, TRANSFORM_ID, "transform error: " + str(error))
