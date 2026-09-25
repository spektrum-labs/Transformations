"""
Transformation: isSSOEnabled
Vendor: Google Workspace
Category: Email Security

Evidence (either shape; the definition decides which it sends):
  * getSSOConfiguration workflow (current): Cloud Identity
      GET https://cloudidentity.googleapis.com/v1/inboundSsoAssignments   -> ssoAssignments
      GET https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles  -> ssoProfiles
    plus the Admin Settings SSO feed for the legacy organization profile     -> legacySso
      GET https://apps-apis.google.com/a/feeds/domain/2.0/{domain}/sso/general
  * getIdentityProvider (previous): the Admin Settings SSO feed alone, as
      {"idpInfo": entry["apps:property"], "rawResponse": ...}.
Scopes: cloud-identity.inboundsso.readonly (assignments, profiles) and
https://apps-apis.google.com/a/feeds/domain/ (legacy feed).

Rule (fail closed). True only when at least one of these is proven:
  * an assignment with ssoMode SAML_SSO whose samlSsoInfo.inboundSamlSsoProfile is a profile
    returned by inboundSamlSsoProfiles with an https idpConfig.singleSignOnServiceUri;
  * an assignment with ssoMode OIDC_SSO (Google's own statement that OIDC SSO is on for it);
  * the legacy organization profile is on (feed enableSSO == "true" AND an https samlSignonUri),
    and either an assignment uses DOMAIN_WIDE_SAML_IF_ENABLED or no assignments are returned
    (tenants that never used SSO profiles report the legacy profile only through the feed).
SSO_OFF, a SAML assignment whose profile is missing or has no https sign-in URL, and
DOMAIN_WIDE_SAML_IF_ENABLED with the legacy profile off all fail. A Google error, a missing
scope ("scope not granted"), or an unreadable body is a data-collection error (unevaluated),
never a pass. A truncated assignment list (nextPageToken) that has not already proven SSO is
unevaluated.

Previously: bool(str(value)) was true for "false" (FP-07), and only the legacy feed was read.
Does not judge: which users are covered (org unit and group targets are reported, not weighed).
"""

import json
from datetime import datetime, timezone

CRITERIA_KEY = "isSSOEnabled"
REQUIRED_SCOPE = ("https://www.googleapis.com/auth/cloud-identity.inboundsso.readonly (SSO profiles) "
                  "and https://apps-apis.google.com/a/feeds/domain/ (organization SSO profile)")


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                "transformationId": CRITERIA_KEY,
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client",
               "insufficient authentication scopes", "access_token_scope_insufficient",
               "request had insufficient authentication"]


def error_text(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if data is None:
        return "No response body"
    if isinstance(data, str):
        return "Empty response body" if data.strip() == "" else ""
    if not isinstance(data, dict):
        return ""
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return " ".join(str(x) for x in [value.get("code") or "", value.get("status") or "",
                                             value.get("message") or ""] if x) or str(value)
        parts = [str(x) for x in [data.get("message"), data.get("vendorAuthError"),
                                  data.get("error_description")] if x]
        return " ".join(parts) if parts else str(value)
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s %s" % (code, data.get("message") or "")
    except (TypeError, ValueError):
        pass
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Integration error")
    return ""


def vendor_error(data):
    """A clear reason when the body is an error, else None. A missing scope in the customer's
    domain-wide delegation grant is named as such, never read as a finding."""
    text = error_text(data)
    if not text:
        return None
    low = text.lower()
    if "missing_credentials" in low:
        return "Google Workspace admin email (subject) is not connected"
    for hint in SCOPE_HINTS:
        if hint in low:
            return ("scope not granted: add %s to Spektrum's domain-wide delegation grant "
                    "(client ID 117073617964097263607) in the Google Admin console. Google said: %s"
                    % (REQUIRED_SCOPE, text[:240]))
    if "service_disabled" in low or "has not been used in project" in low:
        return "Google API not enabled for Spektrum's service account project: %s" % text[:240]
    return text[:300]


def is_true(value):
    """Google bodies reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def parse_time(value):
    if value is None or str(value).strip() == "":
        return None
    parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def find_dict_with(data, key, depth=0):
    """The first dict (breadth-first through dict values, depth-limited) that has `key`."""
    frontier = [data]
    for level in range(5):
        next_frontier = []
        for node in frontier:
            if isinstance(node, dict):
                if key in node:
                    return node
                for value in node.values():
                    if isinstance(value, dict):
                        next_frontier.append(value)
        frontier = next_frontier
    return None


def not_measured(reason, validation, recommendation=None, result_extra=None):
    result = {CRITERIA_KEY: False}
    for k in (result_extra or {}):
        result[k] = result_extra[k]
    return create_response(
        result=result,
        validation=validation,
        api_errors=[reason],
        fail_reasons=["Not measured: " + reason],
        recommendations=[recommendation] if recommendation else []
    )


def read_legacy(data):
    """(dict name -> value, error or None) from the legacy feed in any of its shapes."""
    props = None
    if isinstance(data, dict):
        if "idpInfo" in data:
            props = data.get("idpInfo")
            if not props and isinstance(data.get("rawResponse"), dict):
                error = vendor_error(data.get("rawResponse"))
                if error is not None:
                    return None, error
        elif isinstance(data.get("rawResponse"), dict):
            raw = data.get("rawResponse")
            error = vendor_error(raw)
            if error is not None:
                return None, error
            entry = raw.get("entry")
            props = entry.get("apps:property") if isinstance(entry, dict) else None
        elif isinstance(data.get("entry"), dict):
            props = data["entry"].get("apps:property")
    elif isinstance(data, list):
        props = data
    if isinstance(props, dict):
        props = [props]
    if not isinstance(props, list) or len(props) == 0:
        return None, "SSO settings feed returned no properties"
    out = {}
    for prop in props:
        if isinstance(prop, dict) and "@name" in prop:
            out[str(prop.get("@name")).strip().lower()] = prop.get("@value")
    if len(out) == 0:
        return None, "SSO settings feed properties could not be read"
    return out, None


def legacy_state(props):
    enabled_raw = props.get("enablesso")
    signon = str(props.get("samlsignonuri") or "").strip()
    enabled = enabled_raw is not None and str(enabled_raw).strip().lower() == "true"
    has_idp = signon.lower().startswith("https://")
    host = signon.split("/")[2] if has_idp and len(signon.split("/")) > 2 else ""
    return enabled and has_idp, enabled_raw, host


def host_of(url):
    parts = str(url or "").split("/")
    return parts[2] if len(parts) > 2 else ""


def evaluate_cloud_identity(data, validation):
    assignments_body = data.get("ssoAssignments") if isinstance(data.get("ssoAssignments"), dict) else find_dict_with(data, "inboundSsoAssignments")
    profiles_body = data.get("ssoProfiles") if isinstance(data.get("ssoProfiles"), dict) else find_dict_with(data, "inboundSamlSsoProfiles")
    for body in (assignments_body, profiles_body):
        error = vendor_error(body) if body is not None else None
        if error is not None:
            return not_measured(error, validation, "Add cloud-identity.inboundsso.readonly to Spektrum's domain-wide delegation grant and re-evaluate")
    if assignments_body is None:
        return not_measured("inbound SSO assignments were not returned", validation)
    if profiles_body is None:
        return not_measured("inbound SAML SSO profiles were not returned", validation)

    assignments = assignments_body.get("inboundSsoAssignments") or []
    profiles = profiles_body.get("inboundSamlSsoProfiles") or []
    if not isinstance(assignments, list) or not isinstance(profiles, list):
        return not_measured("inbound SSO response could not be read", validation)
    truncated = bool(assignments_body.get("nextPageToken"))

    profile_hosts = {}
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        idp = profile.get("idpConfig") if isinstance(profile.get("idpConfig"), dict) else {}
        uri = str(idp.get("singleSignOnServiceUri") or "").strip()
        profile_hosts[str(profile.get("name") or "")] = host_of(uri) if uri.lower().startswith("https://") else ""

    legacy_body = data.get("legacySso")
    legacy_on, legacy_raw, legacy_host, legacy_error = False, None, "", None
    if legacy_body is not None:
        props, legacy_error = read_legacy(legacy_body)
        if props is not None:
            legacy_on, legacy_raw, legacy_host = legacy_state(props)

    effective = []
    findings = []
    modes = []
    domain_wide = False
    for a in assignments:
        if not isinstance(a, dict):
            continue
        mode = str(a.get("ssoMode") or "")
        modes.append(mode)
        target = a.get("targetOrgUnit") or a.get("targetGroup") or "unknown target"
        if mode == "SAML_SSO":
            info = a.get("samlSsoInfo") if isinstance(a.get("samlSsoInfo"), dict) else {}
            name = str(info.get("inboundSamlSsoProfile") or "")
            host = profile_hosts.get(name, None)
            if host:
                effective.append("%s: SAML SSO via %s" % (target, host))
            else:
                findings.append({"metric": "samlAssignment", "value": False,
                                 "reason": "%s assigned SAML profile %s, which %s" % (
                                     target, name or "(none)", "has no https sign-in URL" if host == "" else "was not returned")})
        elif mode == "OIDC_SSO":
            effective.append("%s: OIDC SSO" % target)
        elif mode == "DOMAIN_WIDE_SAML_IF_ENABLED":
            domain_wide = True
            if legacy_on:
                effective.append("%s: organization SSO profile via %s" % (target, legacy_host))
            else:
                findings.append({"metric": "domainWideAssignment", "value": False,
                                 "reason": "%s uses the organization SSO profile, which is %s" % (
                                     target, "not readable (%s)" % legacy_error if legacy_error else "off (enableSSO=%r)" % legacy_raw)})
    if not assignments and legacy_on:
        effective.append("organization SSO profile via %s (no SSO profile assignments returned)" % legacy_host)

    result_value = len(effective) > 0
    summary = {"assignments": len(assignments), "samlProfiles": len(profiles), "modes": sorted(set(modes)),
               "legacyEnableSSO": legacy_raw, "truncated": truncated}
    if not result_value and truncated:
        return not_measured("SSO assignment list was truncated before SSO was found", validation, result_extra={})
    if result_value:
        return create_response(result={CRITERIA_KEY: True}, validation=validation,
                               pass_reasons=["SSO is on: " + "; ".join(effective[:5])],
                               additional_findings=findings, input_summary=summary)
    reasons = ["No org unit or group is assigned working SSO (%d assignments, modes %s)" % (len(assignments), sorted(set(modes)) or "none")]
    if legacy_error and not domain_wide:
        reasons.append("Organization SSO profile not readable: %s" % legacy_error)
    return create_response(result={CRITERIA_KEY: False}, validation=validation, fail_reasons=reasons,
                           recommendations=["Assign a SAML or OIDC SSO profile with a third-party identity provider in the Admin console (Security > Authentication > SSO with third-party IdP)"],
                           additional_findings=findings, input_summary=summary)


def evaluate_legacy(data, validation):
    props, error = read_legacy(data)
    if error is not None:
        return not_measured(error, validation, "Check the Google service account's access to the SSO settings feed and re-evaluate")
    result_value, enabled_raw, host = legacy_state(props)
    findings = [
        {"metric": "enableSSO", "value": str(enabled_raw).strip().lower() == "true", "reason": "reported %r" % enabled_raw},
        {"metric": "samlSignonUri", "value": bool(host), "reason": host or "not set"},
    ]
    if result_value:
        return create_response(result={CRITERIA_KEY: True}, validation=validation,
                               pass_reasons=["SAML SSO is enabled for the domain with identity provider %s" % host],
                               additional_findings=findings, input_summary={"enableSSO": enabled_raw, "identityProviderHost": host})
    if enabled_raw is None:
        reason = "SSO settings feed did not report enableSSO; SSO not proven"
    elif str(enabled_raw).strip().lower() != "true":
        reason = "SAML SSO is not enabled (enableSSO=%r)" % enabled_raw
    else:
        reason = "enableSSO is true but no https samlSignonUri is configured"
    return create_response(result={CRITERIA_KEY: False}, validation=validation, fail_reasons=[reason],
                           recommendations=["Configure SSO with a third-party identity provider in the Admin console"],
                           additional_findings=findings, input_summary={"enableSSO": enabled_raw, "identityProviderHost": host})


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if isinstance(data, dict) and "result" in data and isinstance(data.get("result"), (dict, list)):
            data = data["result"]

        error = vendor_error(data)
        if error is not None:
            return not_measured(error, validation, "Check Spektrum's domain-wide delegation grant and re-evaluate")
        if isinstance(data, dict) and ("ssoAssignments" in data or "ssoProfiles" in data
                                       or find_dict_with(data, "inboundSsoAssignments") is not None
                                       or find_dict_with(data, "inboundSamlSsoProfiles") is not None):
            return evaluate_cloud_identity(data, validation)
        return evaluate_legacy(data, validation)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
