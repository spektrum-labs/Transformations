"""
Transformation: isFreeOfConnectWiseCompromiseIndicators
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management

Threat: abuse of the ConnectWise Cloud Backup (506e08f9-6e9a-4da4-942b-a099a03644ae) and
ConnectWise Cloud Management - MS Teams (24205314-2b89-4e07-a2a4-579e898a5640) multitenant OAuth
apps, from 15 Oct 2026. Scope: 7 ConnectWise apps (J.J. 18 Oct 2026): these two and the five other
Cloud Management apps listed in isfreeofconnectwiseappexposure.py beside this file.

Criterion: True when the service-principal (presence) feed, the three sign-in feeds and the directory-audit feed were read whole, the
window start is still inside Entra's 30-day log retention, and they show none of the published indicators since 2026-10-13T00:00:00Z. False when any
readable feed shows one (an indicator found is evidence even if another feed failed).
Indicators:
  - a sign-in from 144.172.64.128 (service principal, interactive or non-interactive user);
  - a ConnectWise app signing in with Python-urllib/3.12, python-requests/2.31 or 2.34.2;
  - credentials added to a ConnectWise service principal;
  - a ConnectWise app adding credentials, roles, grants or owners anywhere (including itself as
    Global Administrator), or such a change made from the indicator IP;
  - the same audit changes where the only link to the apps is the exact published display name (a
    deleted service principal leaves nothing else). These count, but are tagged "Name only, needs
    confirmation before any action" and counted in nameOnlyMatches; other ConnectWise or SkyKick apps
    (Automate, ScreenConnect, SkyKick Migration) never match;
  - a Defender alert titled "Verified Threat Actor IP" or "Graph API activity from a Microsoft
    threat intelligence IP address", or "Suspicious sign-in" naming an indicator.
Defender alerts (Graph security/alerts_v2, SecurityAlert.Read.All) are optional: most connections
do not grant that permission, so an unreadable alert feed does not block True. Every outcome (True,
False and Not evaluated) then says "Defender alerts were not read", so no result implies Defender was
covered (decision 18 Oct 2026).

Data source: Integration-Service workflow getConnectWiseOAuthEvidence (shared by both criteria):
  spSignInsByApp            GET /beta/auditLogs/signIns?$filter=signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge 2026-10-13T00:00:00Z and (appId eq ... or appId eq ...)
  spSignInsFromIndicatorIp  GET /beta/auditLogs/signIns?$filter=signInEventTypes/any(t: t eq 'servicePrincipal') and createdDateTime ge 2026-10-13T00:00:00Z and ipAddress eq '144.172.64.128'
  userSignInsFromIndicatorIp GET /beta/auditLogs/signIns?$filter=signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser') and createdDateTime ge ... and ipAddress eq '144.172.64.128'
                            (a separate read: Graph documents that user and service-principal event types
                            cannot be combined in one filter)
                            (AuditLog.Read.All plus Directory.Read.All; sign-in logs need Entra ID P1 or P2)
  directoryAudits           GET /v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge 2026-10-13T00:00:00Z  (AuditLog.Read.All;
                            category is not a documented filter, so this file picks the activities)
  securityAlerts            GET /v1.0/security/alerts_v2?$filter=createdDateTime ge 2026-10-13T00:00:00Z   (optional)
  plus the presence and grant feeds the sibling file reads, so both files report one verdict.
Entra keeps sign-in and audit logs for 30 days with P1/P2 and 7 days without. Without P1/P2 the
sign-in reads are refused, so the check is Not evaluated there. With P1/P2, once the window start is
30 days old (12 Nov 2026) a clean read reads Not evaluated; an indicator found still reads False.

Not evaluated (None and dataCollection.status "error"): no indicator found and a sign-in feed or the
audit feed is missing, refused, errored or paged, or the window has aged out of log retention. An
indicator in a partial (paged) feed still counts.
"""
import json
from datetime import datetime

KEY = "isFreeOfConnectWiseCompromiseIndicators"
TRANSFORMATION_ID = "isfreeofconnectwisecompromiseindicators"

# ---- shared helper block: start (identical in both criterion files; a test pins it)
# Scope: 7 ConnectWise apps (J.J. 18 Oct 2026). The two the advisories name as abused, then the five other Cloud
# Management apps whose ids Huntress ("ConnectWise (SkyKick) Vendor Credentials Abused in M365 Attacks", 16-17 Oct)
# and BleepingComputer (Oct 2026) publish, and which Huntress says to disable until they can be verified.
CONNECTWISE_APPS = {
    "506e08f9-6e9a-4da4-942b-a099a03644ae": "ConnectWise Cloud Backup (formerly SkyKick Backup)",
    "24205314-2b89-4e07-a2a4-579e898a5640": "ConnectWise Cloud Management - MS Teams",
    "2399d300-6fca-4e6a-a686-399fefe75b83": "ConnectWise Cloud Management",
    "b78f6a77-d4e5-46fb-87e5-d1648bd02519": "ConnectWise Cloud Management - Exchange Online",
    "0de14c77-b9b0-4137-9360-34878a929827": "ConnectWise Cloud Management - MS Graph",
    "412dcf96-176d-4b3a-a1b0-4981ad66971e": "ConnectWise Cloud Management - Partner Center",
    "b2b55f5b-7758-4719-8d8f-88ae172e6bdb": "ConnectWise Cloud Management - SharePoint Online",
}
# Published indicators (Microsoft Threat Intelligence and Huntress, 16-17 Oct 2026). Data, not logic.
INDICATOR_IPS = ("144.172.64.128",)
# Matched as a lowercase prefix, and only on a sign-in by one of the seven apps. curl/7.88.1: Huntress, "ConnectWise
# (SkyKick) Vendor Credentials Abused in M365 Attacks" (16-17 Oct 2026) IOC table, seen on the attacker's password spray.
INDICATOR_USER_AGENTS = ("python-urllib/3.12", "python-requests/2.31", "python-requests/2.34.2", "curl/7.88.1")
# Window start 13 Oct 2026: Huntress says to review credentials and app changes since 13 Oct (the password spray from
# the indicator IP ran 13-14 Oct; the app sign-ins began 15 Oct). One start for sign-ins, audit changes and alerts, so
# the log-retention guard below is measured from the earliest day any check needs.
WINDOW_START = "2026-10-13T00:00:00"
WINDOW_START_DT = datetime(2026, 10, 13)
# Entra keeps sign-in and audit logs 30 days with P1/P2 (the sign-in reads need P1/P2, so a tenant whose
# sign-in reads succeed keeps 30 days). Once the window start is older than that, a clean read can no
# longer show the start of the activity, so "no indicators" is not evaluated.
LOG_RETENTION_DAYS = 30
# Microsoft Graph application permissions (app role ids, identical in every tenant) that let an app
# take over a directory. Directory.ReadWrite.All is the one named in the advisory.
HIGH_RISK_APP_ROLES = {
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
}
HIGH_RISK_SCOPES = ("directory.readwrite.all", "rolemanagement.readwrite.directory",
                    "application.readwrite.all", "approleassignment.readwrite.all")
# Entra built-in role template ids (identical in every tenant).
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
}
CREDENTIAL_ACTIVITIES = (
    "add service principal credentials",
    "update application - certificates and secrets management",
)
PRIVILEGE_ACTIVITIES = (
    "add member to role",
    "add eligible member to role",
    "add app role assignment to service principal",
    "add delegated permission grant",
    "consent to application",
    "add owner to service principal",
    "add owner to application",
)
ALERT_TITLES = ("verified threat actor ip", "graph api activity from a microsoft threat intelligence ip address")
GENERIC_ALERT_TITLES = ("suspicious sign-in",)
APP_ROLE_FEEDS = {
    "506e08f9-6e9a-4da4-942b-a099a03644ae": ("cwBackupAppRoles", "cwBackupDelegatedGrants"),
    "24205314-2b89-4e07-a2a4-579e898a5640": ("cwTeamsAppRoles", "cwTeamsDelegatedGrants"),
    "2399d300-6fca-4e6a-a686-399fefe75b83": ("cwMgmtAppRoles", "cwMgmtDelegatedGrants"),
    "b78f6a77-d4e5-46fb-87e5-d1648bd02519": ("cwExchangeAppRoles", "cwExchangeDelegatedGrants"),
    "0de14c77-b9b0-4137-9360-34878a929827": ("cwGraphAppRoles", "cwGraphDelegatedGrants"),
    "412dcf96-176d-4b3a-a1b0-4981ad66971e": ("cwPartnerCenterAppRoles", "cwPartnerCenterDelegatedGrants"),
    "b2b55f5b-7758-4719-8d8f-88ae172e6bdb": ("cwSharePointAppRoles", "cwSharePointDelegatedGrants"),
}
# The reads cover all seven apps only when every app's role feed is in the body (as data or a stepError marker).
# A body from reads scoped to fewer apps cannot show the others absent, so absence and a clean indicator read
# need this; a present app or an indicator found still counts without it.
SCOPE_NOTE = ("the reads do not cover all seven ConnectWise apps (the per-app feeds of some are missing), so "
              "their absence is not shown")
WRAPPER_KEYS = ("apiResponse", "api_response", "response", "result", "Output")
# Exact display names of the seven apps (and their former SkyKick names), normalised by norm_name. App-initiated
# audit entries often carry a null appId, and a deleted app's service principal id is no longer in the presence
# feed, so the name can be the only link. It is compared by equality, never as a substring: MSP tenants run other
# ConnectWise and SkyKick apps (Automate, Manage, ScreenConnect, Control, SkyKick Migration) whose routine credential
# rotations are not indicators. No advisory shows a suffixed variant, so none is accepted. Sources:
#   Microsoft Threat Intelligence on X, 16 Oct 2026: "ConnectWise Cloud Backup (AppId: 506e08f9-...), formerly
#     SkyKick Backup";
#   Huntress, "ConnectWise (SkyKick) Vendor Credentials Abused in M365 Attacks", 16-17 Oct 2026: "ConnectWise Cloud
#     Backup" ("SkyKick Backup" in its IOC table) and "ConnectWise Cloud Management - MS Teams", formerly "SkyKick
#     Cloud Manager - MS Teams";
#   Coalition, 16 Oct 2026: shown in Entra as "SkyKick Backup" or "ConnectWise Cloud Backup", formerly "SkyKick Cloud
#     Backup";
#   Huntress and BleepingComputer: the five other "ConnectWise Cloud Management" names below, and "In older tenants the
#     Cloud Management apps may appear as 'SkyKick Cloud Manager'" (no suffixed SkyKick name is published for them).
# A match by name alone is still an indicator (fail closed), but it is tagged: it needs confirmation before action.
CONNECTWISE_APP_NAMES = (
    "connectwise cloud backup", "skykick backup", "skykick cloud backup",
    "connectwise cloud management - ms teams", "skykick cloud manager - ms teams",
    "connectwise cloud management", "connectwise cloud management - exchange online",
    "connectwise cloud management - ms graph", "connectwise cloud management - partner center",
    "connectwise cloud management - sharepoint online", "skykick cloud manager",
)
NAME_ONLY_PREFIX = "Name only, needs confirmation before any action: "


def create_response(result, pass_reasons=None, fail_reasons=None, input_summary=None, api_errors=None,
                    transformation_errors=None, findings=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if transformation_errors else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORMATION_ID, "vendor": "Microsoft",
                         "category": "Identity and Access Management"},
        },
    }


def utc_now():
    return datetime.utcnow()


today = utc_now


def retention_covers_window():
    age = today() - WINDOW_START_DT
    return age.days < LOG_RETENTION_DAYS


def lower(value):
    return value.strip().lower() if isinstance(value, str) else ""


def norm_activity(value):
    text = lower(value)
    for dash in ("–", "—", "‐", "‑", "‒", "−"):
        text = text.replace(dash, "-")
    return " ".join(text.split())


def norm_name(value):
    """A display name for an exact comparison: lowercase, single spaces, one kind of dash with a space each side."""
    return " ".join(norm_activity(value).replace("-", " - ").split())


def in_window(stamp):
    """True when the timestamp is on or after the window start, or cannot be read (an indicator with
    an unreadable time still counts)."""
    if not isinstance(stamp, str) or len(stamp) < 19:
        return True
    return stamp[:19] >= WINDOW_START


def unwrap(data):
    if isinstance(data, str):
        data = json.loads(data) if data.strip() else None
    elif isinstance(data, bytes):
        data = json.loads(data.decode("utf-8"))
    if isinstance(data, dict) and "data" in data and "validation" in data:
        validation = data.get("validation")
        if isinstance(validation, dict) and validation.get("status") == "failed":
            return None
        data = data.get("data")
    for attempt in range(3):
        if not isinstance(data, dict):
            break
        moved = False
        for key in WRAPPER_KEYS:
            if isinstance(data.get(key), dict):
                data = data[key]
                moved = True
                break
        if not moved:
            break
    return data if isinstance(data, dict) else None


def read_feed(data, key):
    """(records, state) for one merged Graph feed. state is ok, missing, error or paged. records is a list
    when state is ok or paged (a paged list is partial: an indicator in it counts, its absence proves
    nothing), else None. Callers that need the whole list check state == "ok"."""
    feed = data.get(key)
    if feed is None:
        return None, "missing"
    state = "ok"
    stats = data.get("paginationStats")
    if isinstance(stats, dict) and isinstance(stats.get(key), dict) and stats[key].get("paginationTruncated") is True:
        state = "paged"
    if isinstance(feed, list):
        records = feed
    elif isinstance(feed, dict):
        if feed.get("stepError") or feed.get("error") or feed.get("errors"):
            return None, "error"
        if feed.get("@odata.nextLink"):
            state = "paged"
        records = feed.get("value")
        if not isinstance(records, list):
            return None, "error"
    else:
        return None, "error"
    for record in records:
        if not isinstance(record, dict):
            return None, "error"
    return records, state


def assess(data):
    """Everything both criteria need, from the merged feeds. Never raises on a well-formed dict."""
    feeds = {}
    sps, state = read_feed(data, "servicePrincipals")
    feeds["servicePrincipals"] = state
    present = []
    presence_known = False
    if state == "ok":
        shaped = [r for r in sps if isinstance(r.get("appId"), str)]
        if sps and not shaped:
            feeds["servicePrincipals"] = "error"
        else:
            presence_known = True
            for record in shaped:
                if lower(record.get("appId")) in CONNECTWISE_APPS:
                    present.append(record)
    sp_ids = []
    for record in present:
        if isinstance(record.get("id"), str):
            sp_ids.append(lower(record.get("id")))
    enabled = [r for r in present if r.get("accountEnabled") is not False]
    scope_ok = True
    for app_id in APP_ROLE_FEEDS:
        if APP_ROLE_FEEDS[app_id][0] not in data:
            scope_ok = False
    feeds["appScope"] = "ok" if scope_ok else "missing feeds for some of the seven apps"

    # Risk: app permissions, delegated grants and directory roles held by a present app.
    high = []
    unknown_risk = False
    roles, roles_state = read_feed(data, "roleAssignments")
    feeds["roleAssignments"] = roles_state
    for record in enabled:
        app_id = lower(record.get("appId"))
        name = CONNECTWISE_APPS.get(app_id, app_id)
        role_feed, grant_feed = APP_ROLE_FEEDS.get(app_id, ("", ""))
        assigned, assigned_state = read_feed(data, role_feed)
        feeds[role_feed] = assigned_state
        if assigned_state == "ok":
            for item in assigned:
                label = HIGH_RISK_APP_ROLES.get(lower(item.get("appRoleId")))
                if label:
                    high.append(name + " holds the application permission " + label)
        else:
            unknown_risk = True
        grants, grants_state = read_feed(data, grant_feed)
        feeds[grant_feed] = grants_state
        if grants_state == "ok":
            for item in grants:
                scopes = lower(item.get("scope")).split()
                for scope in HIGH_RISK_SCOPES:
                    if scope in scopes:
                        high.append(name + " holds a delegated grant including " + scope)
        else:
            unknown_risk = True
        sp_id = lower(record.get("id"))
        if roles_state == "ok":
            for item in roles:
                if lower(item.get("principalId")) == sp_id and lower(item.get("roleDefinitionId")) in PRIVILEGED_ROLES:
                    high.append(name + " holds the directory role " + PRIVILEGED_ROLES[lower(item.get("roleDefinitionId"))])
        else:
            unknown_risk = True

    # Indicators of compromise since the window start.
    indicators = []
    name_only = []
    by_app, by_app_state = read_feed(data, "spSignInsByApp")
    by_ip, by_ip_state = read_feed(data, "spSignInsFromIndicatorIp")
    by_user_ip, by_user_ip_state = read_feed(data, "userSignInsFromIndicatorIp")
    feeds["spSignInsByApp"] = by_app_state
    feeds["spSignInsFromIndicatorIp"] = by_ip_state
    feeds["userSignInsFromIndicatorIp"] = by_user_ip_state
    sign_ins = (by_app or []) + (by_ip or []) + (by_user_ip or [])
    # The apps' service principal ids, also from feeds other than the presence read, so an audit entry
    # initiated by one still matches when the presence read failed.
    for item in by_app or []:
        if lower(item.get("appId")) in CONNECTWISE_APPS and lower(item.get("servicePrincipalId")):
            sp_ids.append(lower(item.get("servicePrincipalId")))
    for app_id in APP_ROLE_FEEDS:
        role_feed, grant_feed = APP_ROLE_FEEDS[app_id]
        assigned, assigned_state = read_feed(data, role_feed)
        for item in assigned or []:
            if lower(item.get("principalId")):
                sp_ids.append(lower(item.get("principalId")))
        grants, grants_state = read_feed(data, grant_feed)
        for item in grants or []:
            if lower(item.get("clientId")):
                sp_ids.append(lower(item.get("clientId")))
    for item in sign_ins:
        if not in_window(item.get("createdDateTime")):
            continue
        ip = lower(item.get("ipAddress"))
        agent = lower(item.get("userAgent"))
        app_id = lower(item.get("appId"))
        if ip in INDICATOR_IPS:
            indicators.append("Sign-in from the indicator IP address " + ip + " at " + str(item.get("createdDateTime")))
        elif app_id in CONNECTWISE_APPS and agent:
            for prefix in INDICATOR_USER_AGENTS:
                if agent.startswith(prefix):
                    indicators.append(CONNECTWISE_APPS[app_id] + " signed in with the indicator user agent " + agent)
                    break
    audits, audits_state = read_feed(data, "directoryAudits")
    feeds["directoryAudits"] = audits_state
    for item in audits or []:
        if not in_window(item.get("activityDateTime")):
            continue
        activity = norm_activity(item.get("activityDisplayName"))
        is_credential = activity in CREDENTIAL_ACTIVITIES
        is_privilege = activity in PRIVILEGE_ACTIVITIES
        if not (is_credential or is_privilege):
            continue
        initiated = item.get("initiatedBy") if isinstance(item.get("initiatedBy"), dict) else {}
        app = initiated.get("app") if isinstance(initiated.get("app"), dict) else {}
        user = initiated.get("user") if isinstance(initiated.get("user"), dict) else {}
        app_name = norm_name(app.get("displayName"))
        by_connectwise = lower(app.get("appId")) in CONNECTWISE_APPS or lower(app.get("servicePrincipalId")) in sp_ids
        from_ioc_ip = lower(user.get("ipAddress")) in INDICATOR_IPS
        on_connectwise = False
        on_name = ""
        for target in item.get("targetResources") or []:
            if not isinstance(target, dict):
                continue
            if lower(target.get("id")) in sp_ids:
                on_connectwise = True
            elif norm_name(target.get("displayName")) in CONNECTWISE_APP_NAMES:
                on_name = norm_name(target.get("displayName"))
        when = str(item.get("activityDateTime"))
        if by_connectwise:
            indicators.append("A ConnectWise app performed '" + activity + "' at " + when)
        elif from_ioc_ip:
            indicators.append("'" + activity + "' from the indicator IP address at " + when)
        elif on_connectwise and is_credential:
            indicators.append("Credentials changed on a ConnectWise service principal ('" + activity + "') at " + when)
        elif app_name in CONNECTWISE_APP_NAMES:
            name_only.append(NAME_ONLY_PREFIX + "an app named '" + app_name + "' performed '" + activity + "' at "
                             + when + ". It matched by display name only (no app or service principal id); confirm "
                             "in the audit entry that it is the ConnectWise app.")
        elif on_name and is_credential:
            name_only.append(NAME_ONLY_PREFIX + "credentials changed on an app named '" + on_name + "' ('" + activity
                             + "') at " + when + ". It matched by display name only (no service principal id); "
                             "confirm in the audit entry that it is the ConnectWise app.")
    indicators.extend(name_only)
    alerts, alerts_state = read_feed(data, "securityAlerts")
    feeds["securityAlerts"] = alerts_state
    for item in alerts or []:
        if not in_window(item.get("createdDateTime")):
            continue
        title = lower(item.get("title"))
        if title in ALERT_TITLES:
            indicators.append("Defender alert '" + str(item.get("title")) + "'")
        elif title in GENERIC_ALERT_TITLES:
            text = json.dumps(item).lower()
            hit = False
            for marker in INDICATOR_IPS + tuple(CONNECTWISE_APPS):
                if marker in text:
                    hit = True
            if hit:
                indicators.append("Defender alert '" + str(item.get("title")) + "' naming an indicator")
    retention_ok = retention_covers_window()
    feeds["logRetention"] = "ok" if retention_ok else "window older than " + str(LOG_RETENTION_DAYS) + " days"
    # The presence read is the only source of the apps' service-principal ids when they have no sign-ins, so
    # without it a credential add on a ConnectWise service principal cannot be ruled out.
    indicators_read = (presence_known and by_app_state == "ok" and by_ip_state == "ok" and by_user_ip_state == "ok"
                       and audits_state == "ok" and retention_ok and scope_ok)

    # A present but disabled app is Exposed at risk low (decision 18 Oct 2026): it can be re-enabled and keeps
    # its consent, grants and credentials, so the customer must remove it, not just leave it disabled.
    absence_known = presence_known and scope_ok
    if indicators:
        verdict = "Indicators found"
    elif presence_known and present:
        verdict = "Exposed"
    elif absence_known:
        verdict = "Not exposed"
    else:
        verdict = "Not evaluated"
    if not enabled:
        if present:
            risk = "low"
        else:
            risk = "none" if absence_known else "unknown"
    elif high:
        risk = "high"
    elif unknown_risk:
        risk = "unknown"
    else:
        risk = "standard"
    names = []
    for record in present:
        label = CONNECTWISE_APPS.get(lower(record.get("appId")), "")
        if record.get("accountEnabled") is False:
            label = label + " (disabled)"
        names.append(label)
    return {
        "presenceKnown": presence_known, "absenceKnown": absence_known, "scopeOk": scope_ok, "present": present, "enabled": enabled, "names": names,
        "high": high, "risk": risk, "indicators": indicators, "indicatorsRead": indicators_read,
        "nameOnly": len(name_only),
        "alertsState": alerts_state, "verdict": verdict, "feeds": feeds,
        "retentionOk": retention_ok,
    }


def summary_fields(found):
    return {
        "connectWiseVerdict": found["verdict"],
        "connectWiseRiskLevel": found["risk"],
        "connectWiseAppsPresent": found["names"],
        "indicatorsFound": len(found["indicators"]),
        "nameOnlyMatches": found["nameOnly"],
    }


def not_measured(reason, found=None, transformation_errors=None):
    result = {KEY: None}
    if found is not None:
        result.update(summary_fields(found))
    else:
        result.update({"connectWiseVerdict": "Not evaluated", "connectWiseRiskLevel": "unknown",
                       "connectWiseAppsPresent": [], "indicatorsFound": 0, "nameOnlyMatches": 0})
    summary = {"feeds": found["feeds"]} if found is not None else {}
    findings = found["indicators"] + found["high"] if found is not None else []
    return create_response(result, fail_reasons=[reason], api_errors=[reason], input_summary=summary,
                           transformation_errors=transformation_errors, findings=findings)
# ---- shared helper block: end


def transform(input):
    try:
        data = unwrap(input)
        if data is None:
            return not_measured("No Microsoft Graph feeds in the response; indicators are not evaluated.")
        found = assess(data)
        summary = {"feeds": found["feeds"]}
        findings = found["indicators"] + found["high"]
        alerts_note = ""
        if found["alertsState"] != "ok":
            alerts_note = "Defender alerts were not read (" + found["alertsState"] + ")."
        if found["indicators"]:
            result = {KEY: False}
            result.update(summary_fields(found))
            reasons = found["indicators"] + ([alerts_note] if alerts_note else [])
            return create_response(result, fail_reasons=reasons, input_summary=summary, findings=findings)
        if not found["retentionOk"]:
            return not_measured(("The indicator window (from 13 Oct 2026) is now older than Entra's "
                                 + str(LOG_RETENTION_DAYS) + "-day sign-in and audit log retention, so a clean "
                                 "read can no longer rule out early activity; indicators are not evaluated. "
                                 + alerts_note).strip(), found)
        if not found["scopeOk"]:
            return not_measured(("No indicator was found, but " + SCOPE_NOTE + "; indicators are not evaluated. "
                                 + alerts_note).strip(), found)
        if not found["presenceKnown"]:
            return not_measured(("No indicator was found, but the service-principal read could not be read whole, "
                                 "so a credential change on a ConnectWise service principal cannot be ruled out; "
                                 "indicators are not evaluated. " + alerts_note).strip(), found)
        if not found["indicatorsRead"]:
            return not_measured(("A sign-in log read or the directory audit log could not be read "
                                 "whole; indicators are not evaluated. Needs AuditLog.Read.All, and Entra ID P1 or P2 "
                                 "for sign-in logs. " + alerts_note).strip(), found)
        result = {KEY: True}
        result.update(summary_fields(found))
        reasons = ["No published indicator in sign-ins (service principal, and user sign-ins from the indicator IP) or the directory audit log since 13 Oct 2026."]
        if alerts_note:
            reasons.append(alerts_note)
        return create_response(result, pass_reasons=reasons, input_summary=summary, findings=findings)
    except Exception as e:
        return not_measured("The Microsoft Graph feeds could not be read; indicators are not evaluated.",
                            transformation_errors=[str(e)])
