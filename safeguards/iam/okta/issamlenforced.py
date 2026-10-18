"""
Transformation: isSAMLEnforced
Vendor: Okta  |  Category: Identity / Application sign-on

Method: listApplications (Integration-Service) -> GET /api/v1/apps?limit=200, Link-header paging
        (pagination {"type": "link_header", "maxPages": 10}), scope okta.apps.read.
Docs:   https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Application/#tag/Application/operation/listApplications
        Application.{id, name, label, status (ACTIVE | INACTIVE), signOnMode,
        settings.oauthClient.application_type}

isSAMLEnforced is True only when every ACTIVE, user-facing app in Okta signs users in through federation, so no
app holds a password of its own, and False as soon as one active user-facing app uses a known password mode:
  * federated:     SAML_2_0, OPENID_CONNECT, SAML_1_1, WS_FEDERATION (the app trusts an Okta-signed assertion or
                   token; WS_FEDERATION is how Okta signs users in to Microsoft 365);
  * not federated: AUTO_LOGIN, BROWSER_PLUGIN, BASIC_AUTH, SECURE_PASSWORD_STORE (password / SWA apps: Okta
                   stores or replays a password that the app itself checks).
Not judged, and listed in additionalFindings so nothing is hidden:
  * INACTIVE apps (nobody can sign in through them);
  * BOOKMARK apps (a link; Okta signs no one in to it);
  * OAuth service apps (OPENID_CONNECT with application_type "service": machine-to-machine, no user);
  * MFA_AS_SERVICE apps (Okta MFA as a service, e.g. the RDP / ADFS MFA integrations: Okta supplies a second
    factor to another system's own sign-in; it is not a user sign-on app);
  * Okta's own built-in apps, matched on Application.name, which Okta reserves (customer apps get generated,
    org-prefixed names): saasure (Okta Admin Console), okta_enduser (Okta Dashboard), okta_browser_plugin
    (Okta Browser Plugin), okta_flow_sso and okta_workflows_oauth (Okta Workflows), okta_atspoke_sso,
    okta_access_requests_resource_catalog (Okta Access Requests) and okta_iga_reviewer (Okta Identity
    Governance). Users sign in to these through Okta itself, so they say nothing about the customer's apps.

Findings name the affected objects: the first fail reason names at most MAX_NAMED (50) non-federated apps by
label and sign-on mode, then "and N more"; inputSummary.affectedApps carries the same 50 and
inputSummary.affectedAppCount the full total.

Unknown sign-on mode: an active, user-facing app whose signOnMode is missing, null or not one of the modes above
is listed as "unknown sign-on mode" (inputSummary.unknownSignOnModeApps, at most 50, and
unknownSignOnModeAppCount). It never makes the answer True:
  * one or more password / SWA apps are active -> False, a definitive answer the unknown apps cannot change
    (they are listed in additionalFindings);
  * every judged app is federated but unknown apps exist -> Not evaluated, naming the unknown apps.

Scope: Okta speaks only for the apps integrated in Okta. An app that signs users in on its own, outside Okta,
is not seen here.

Not evaluated (isSAMLEnforced None, dataCollection status "error"), never a pass, on: an empty or missing body;
an error body, an HTTP status of 400 or more, or Integration-Service's vendorErrorAsResponse marker (a 403 means
the API credential cannot read apps: okta.apps.read plus an admin role); a body that is not a list of apps; a
read that was not finished (paginationTruncated / truncated set at any level, or an unread next link); a list
of READ_CAP (2000 = limit 200 x maxPages 10) apps or more, because the read may have stopped at maxPages; an app
record that is not an object or carries an unrecognised status; no password / SWA app but one or more apps with
an unknown sign-on mode (above); no active user-facing app left to judge after the exclusions above; any
exception.
"""

import json
from datetime import datetime, timezone

KEY = "isSAMLEnforced"
TOOL = "Okta"
ENDPOINT = "GET /api/v1/apps"
MAX_NAMED = 50
MAX_NAME_LEN = 100
READ_CAP = 2000
FEDERATED_MODES = ["SAML_2_0", "OPENID_CONNECT", "SAML_1_1", "WS_FEDERATION"]
PASSWORD_MODES = ["AUTO_LOGIN", "BROWSER_PLUGIN", "BASIC_AUTH", "SECURE_PASSWORD_STORE"]
BOOKMARK_MODES = ["BOOKMARK"]
MFA_SERVICE_MODES = ["MFA_AS_SERVICE"]
ACTIVE_STATUSES = ["ACTIVE"]
INACTIVE_STATUSES = ["INACTIVE", "DELETED"]
OKTA_BUILTIN_APP_NAMES = [
    "saasure",
    "okta_enduser",
    "okta_browser_plugin",
    "okta_flow_sso",
    "okta_workflows_oauth",
    "okta_atspoke_sso",
    "okta_access_requests_resource_catalog",
    "okta_iga_reviewer",
]
WRAPPERS = ["data", "apiResponse", "response", "result", "Output", "rawResponse", "_response_data"]


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None, input_summary=None,
                    api_errors=None, transformation_errors=None, additional_findings=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": TOOL,
                "category": "Identity",
            },
        },
    }


def unevaluated(reason, summary=None, transformation_errors=None, additional_findings=None, limit=500):
    """Nothing was measured: the key is None, never True and never False."""
    text = str(reason)[:limit]
    return create_response({KEY: None}, fail_reasons=["Not evaluated: " + text], api_errors=[text],
                           input_summary=summary, transformation_errors=transformation_errors,
                           additional_findings=additional_findings)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def text_of(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value)
        except Exception:
            return str(value)
    return str(value)


def as_upper(value):
    if value is None:
        return ""
    return str(value).strip().upper()


def flag_set(value):
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return str(value).strip().lower() in ("true", "1", "yes")


def link_text(value):
    text = str(value or "").strip()
    return "" if text in ("None", "null") else text


def status_code_of(value):
    for k in ("statusCode", "status_code"):
        code = value.get(k)
        if isinstance(code, bool):
            continue
        if isinstance(code, int):
            return code
        if isinstance(code, str) and code.strip().isdigit():
            return int(code.strip())
    return None


def level_problem(value):
    """Why one dict level of the response cannot be read as a complete app list, '' when nothing says so."""
    if "vendorErrorAsResponse" in value:
        marker = value.get("vendorErrorAsResponse")
        status = marker.get("status") if isinstance(marker, dict) else None
        if status == 403:
            return ("Okta refused " + ENDPOINT + " with HTTP 403: the API credential cannot read apps (it needs "
                    "the okta.apps.read scope and an admin role that can view applications)")
        return "Okta refused " + ENDPOINT + " (HTTP " + str(status)[:10] + ")"
    for k in ("errorCode", "errorSummary", "error", "errors", "errorMessage"):
        if value.get(k):
            return "Okta returned an error for " + ENDPOINT + ": " + text_of(value.get(k))[:200]
    code = status_code_of(value)
    if code is not None and code >= 400:
        return "Okta answered " + ENDPOINT + " with HTTP " + str(code)
    blocks = [value]
    for k in ("response_metadata", "metadata", "pagination"):
        if isinstance(value.get(k), dict):
            blocks.append(value[k])
    for block in blocks:
        for k in ("paginationTruncated", "truncated"):
            if k in block and flag_set(block.get(k)):
                return "the app list was not read to the end (" + k + " is set)"
    links = value.get("_links")
    if isinstance(links, dict) and isinstance(links.get("next"), dict):
        if link_text(links["next"].get("href")) or flag_set(links["next"].get("truncated")):
            return "the app list was not read to the end (a next page link remains)"
    return ""


def app_list(data):
    """(apps, problem): the app list under any Integration-Service / Token-Service wrapper, checking every
    level for an error or truncation marker on the way down."""
    for _ in range(6):
        if isinstance(data, list):
            return data, ""
        if not isinstance(data, dict):
            return None, "the response is not a list of apps"
        problem = level_problem(data)
        if problem:
            return None, problem
        inner = None
        for k in WRAPPERS:
            if k in data and isinstance(data.get(k), (list, dict, str)):
                inner = data.get(k)
                break
        if inner is None:
            return None, "the response is not a list of apps"
        data = decode(inner)
    return None, "the response is not a list of apps"


def clip(value):
    return str(value).strip()[:MAX_NAME_LEN]


def app_label(app):
    for value in (app.get("label"), app.get("name"), app.get("id")):
        if value not in (None, ""):
            return clip(value)
    return "(unnamed app)"


def is_service_app(app):
    settings = app.get("settings")
    oauth = settings.get("oauthClient") if isinstance(settings, dict) else None
    kind = oauth.get("application_type") if isinstance(oauth, dict) else None
    return as_upper(kind) == "SERVICE"


def name_list(items, cap):
    shown = ", ".join(items[:cap])
    if len(items) > cap:
        shown = shown + " and " + str(len(items) - cap) + " more"
    return shown


def evaluate(input):
    apps, problem = app_list(decode(input))
    if problem:
        return unevaluated(problem)
    if not apps:
        return unevaluated(ENDPOINT + " returned no apps; every Okta org has built-in apps, so this is a failed "
                           "or empty read")
    if len(apps) >= READ_CAP:
        return unevaluated(str(len(apps)) + " apps were read, the most one read returns (" + str(READ_CAP)
                           + " = 200 per page x 10 pages); the list may have been cut at maxPages")

    federated = []
    affected = []
    inactive = []
    bookmarks = []
    service = []
    mfa_service = []
    unknown = []
    builtin = []
    for app in apps:
        if not isinstance(app, dict):
            return unevaluated("an app record in " + ENDPOINT + " is not an object")
        label = app_label(app)
        status = as_upper(app.get("status"))
        if status in INACTIVE_STATUSES:
            inactive.append(label)
            continue
        if status not in ACTIVE_STATUSES:
            return unevaluated("app " + label + " has an unrecognised status '" + clip(status) + "'")
        if str(app.get("name") or "").strip().lower() in OKTA_BUILTIN_APP_NAMES:
            builtin.append(label)
            continue
        mode = as_upper(app.get("signOnMode"))
        if mode in BOOKMARK_MODES:
            bookmarks.append(label)
            continue
        if mode in MFA_SERVICE_MODES:
            mfa_service.append(label)
            continue
        if mode in FEDERATED_MODES:
            if mode == "OPENID_CONNECT" and is_service_app(app):
                service.append(label)
                continue
            federated.append(label)
            continue
        if mode in PASSWORD_MODES:
            affected.append(label + " (" + mode + ")")
            continue
        unknown.append(label + " (signOnMode " + (clip(mode) if mode not in ("", "NONE", "NULL") else "missing")
                       + ")")

    judged = len(federated) + len(affected)
    summary = {
        "appsRead": len(apps),
        "activeUserFacingAppCount": judged,
        "federatedAppCount": len(federated),
        "affectedApps": affected[:MAX_NAMED],
        "affectedAppCount": len(affected),
        "inactiveAppCount": len(inactive),
        "bookmarkAppCount": len(bookmarks),
        "serviceAppCount": len(service),
        "mfaAsServiceAppCount": len(mfa_service),
        "unknownSignOnModeApps": unknown[:MAX_NAMED],
        "unknownSignOnModeAppCount": len(unknown),
        "oktaBuiltInApps": builtin[:MAX_NAMED],
        "federatedModes": FEDERATED_MODES,
        "passwordModes": PASSWORD_MODES,
    }
    findings = []
    if builtin:
        findings.append(TOOL + ": " + str(len(builtin)) + " Okta built-in app(s) not judged: "
                        + name_list(builtin, MAX_NAMED))
    if bookmarks:
        findings.append(TOOL + ": " + str(len(bookmarks)) + " bookmark app(s) not judged (Okta signs no one in "
                        "to a bookmark): " + name_list(bookmarks, MAX_NAMED))
    if service:
        findings.append(TOOL + ": " + str(len(service)) + " OAuth service app(s) not judged (machine-to-machine, "
                        "no user sign-in)")
    if mfa_service:
        findings.append(TOOL + ": " + str(len(mfa_service)) + " MFA-as-a-service app(s) not judged (Okta adds a "
                        "second factor to another system's own sign-in; not a user sign-on app): "
                        + name_list(mfa_service, MAX_NAMED))
    if inactive:
        findings.append(TOOL + ": " + str(len(inactive)) + " inactive app(s) not judged")
    unknown_line = ""
    if unknown:
        unknown_line = (TOOL + ": " + str(len(unknown)) + " active app(s) with an unknown sign-on mode (missing or "
                        "unrecognised sign-on mode), not judged: " + name_list(unknown, MAX_NAMED))

    scope = TOOL + " (apps integrated in Okta)"
    if affected:
        line = (scope + ": " + str(len(affected)) + " of " + str(judged) + " active user-facing apps sign users in "
                "with a password (password / SWA apps), not through SAML or OIDC federation: "
                + name_list(affected, MAX_NAMED))
        if unknown_line:
            findings.append(unknown_line)
        return create_response(
            {KEY: False}, fail_reasons=[line], input_summary=summary, additional_findings=findings,
            recommendations=["Move each named app to SAML 2.0 or OpenID Connect sign-on in Okta (Applications > "
                             "the app > Sign On), or retire it. Password and SWA apps keep a password the app "
                             "itself checks."])
    if unknown:
        others = ("the other " + str(judged) + " active user-facing app(s) are federated (SAML / OIDC)" if judged
                  else "no other active user-facing app was found")
        return unevaluated(unknown_line + ". No password / SWA app is active and " + others + ", but an app whose "
                           "sign-on mode cannot be read may hold a password, so SAML / OIDC enforcement cannot be "
                           "confirmed", summary=summary, additional_findings=findings, limit=12000)
    if judged == 0:
        return unevaluated("no active user-facing app was found to judge (only Okta built-in, bookmark, service, "
                           "MFA-as-a-service or inactive apps were read)", summary=summary,
                           additional_findings=findings)
    line = (scope + ": all " + str(judged) + " active user-facing apps sign users in through SAML or OIDC "
            "federation; no password / SWA app is active. Apps that sign users in outside Okta are not seen.")
    return create_response({KEY: True}, pass_reasons=[line], input_summary=summary, additional_findings=findings)


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200], transformation_errors=[str(e)[:200]])
