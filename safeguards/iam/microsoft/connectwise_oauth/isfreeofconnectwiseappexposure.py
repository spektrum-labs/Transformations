"""
Transformation: isFreeOfConnectWiseAppExposure
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management

Threat: abuse of ConnectWise multitenant OAuth apps (Microsoft Threat Intelligence and Huntress,
16-17 Oct 2026). A threat actor used customers' existing consent to these apps to get tokens in
customer tenants, ran Graph reconnaissance and added credentials to service principals. Scope: 7
ConnectWise apps (J.J. 18 Oct 2026), app ids as published by Huntress and BleepingComputer:
  ConnectWise Cloud Backup (formerly SkyKick Backup)   appId 506e08f9-6e9a-4da4-942b-a099a03644ae
  ConnectWise Cloud Management - MS Teams              appId 24205314-2b89-4e07-a2a4-579e898a5640
  ConnectWise Cloud Management                         appId 2399d300-6fca-4e6a-a686-399fefe75b83
  ConnectWise Cloud Management - Exchange Online       appId b78f6a77-d4e5-46fb-87e5-d1648bd02519
  ConnectWise Cloud Management - MS Graph              appId 0de14c77-b9b0-4137-9360-34878a929827
  ConnectWise Cloud Management - Partner Center        appId 412dcf96-176d-4b3a-a1b0-4981ad66971e
  ConnectWise Cloud Management - SharePoint Online     appId b2b55f5b-7758-4719-8d8f-88ae172e6bdb
The first two are the ones the advisories name as abused; Huntress says to disable the others until
they can be verified. Each app counts the same way (presence, grants, roles and indicators).

Criterion: True when the tenant's service-principal list was read, the reads cover all seven apps,
and none of them has a service principal in it. False when any app is present (Exposed). A present but disabled service principal
is Exposed at risk low (decision 18 Oct 2026): it can be re-enabled and keeps its consent, grants and
credentials, so the fail reason tells the customer to remove it, not just leave it disabled.

Data source: Integration-Service workflow getConnectWiseOAuthEvidence (shared by both criteria), merged Graph reads:
  servicePrincipals         GET /v1.0/servicePrincipals?$filter=appId in (...)          (Application.Read.All or Directory.Read.All)
  cw<App>AppRoles           GET /v1.0/servicePrincipals(appId='...')/appRoleAssignments     one per app (APP_ROLE_FEEDS)
  cw<App>DelegatedGrants    GET /v1.0/servicePrincipals(appId='...')/oauth2PermissionGrants one per app
                            Every app's role feed must be in the body (data or a stepError marker, for example
                            404 when the app is absent); otherwise absence is Not evaluated.
  roleAssignments           GET /v1.0/roleManagement/directory/roleAssignments           (RoleManagement.Read.Directory or Directory.Read.All)
  spSignInsByApp, spSignInsFromIndicatorIp, userSignInsFromIndicatorIp, directoryAudits, securityAlerts
                            (see the sibling file)
Every step runs with continueOnError, so a refused read arrives as {"stepError": true, ...}.

Verdict fields (identical in both criterion files):
  connectWiseVerdict     Not evaluated | Not exposed | Exposed | Indicators found
  connectWiseRiskLevel   high (Directory.ReadWrite.All or a peer permission, or a privileged
                         directory role such as Global Administrator) | standard | unknown (a
                         grant, delegated-grant or role feed for an enabled app could not be read) |
                         low (present, but every present app is disabled) | none
  indicatorsFound        indicators found since 13 Oct 2026
  nameOnlyMatches        how many of them matched the apps by exact display name only (no app or service
                         principal id): still indicators, but each needs confirmation before any action
Not evaluated (None and dataCollection.status "error"): the service-principal feed is missing,
refused, errored, paged or unrecognised. A failed read is never "not exposed".
"""
import json
from datetime import datetime

KEY = "isFreeOfConnectWiseAppExposure"
TRANSFORMATION_ID = "isfreeofconnectwiseappexposure"

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
            return not_measured("No Microsoft Graph feeds in the response; exposure is not evaluated.")
        found = assess(data)
        if not found["presenceKnown"]:
            return not_measured("The service-principal list could not be read whole ("
                                + found["feeds"].get("servicePrincipals", "missing")
                                + "); exposure is not evaluated. Grant Application.Read.All or Directory.Read.All.", found)
        if not found["present"] and not found["absenceKnown"]:
            return not_measured("No ConnectWise app was found, but " + SCOPE_NOTE + "; exposure is not evaluated.",
                                found)
        result = {KEY: not found["present"]}
        result.update(summary_fields(found))
        summary = {"feeds": found["feeds"]}
        findings = found["indicators"] + found["high"]
        if found["enabled"]:
            reasons = ["Enabled in this tenant: " + ", ".join(found["names"])]
            reasons = reasons + found["high"]
            if found["risk"] == "unknown":
                reasons.append("The app's permissions or directory roles could not be read; risk level unknown.")
            return create_response(result, fail_reasons=reasons, input_summary=summary, findings=findings)
        if found["present"]:
            reasons = ["Present but disabled: " + ", ".join(found["names"]),
                       "A disabled app can be re-enabled and keeps its consent, grants and credentials. Remove it: "
                       "delete its service principal and revoke its consent; do not just leave it disabled."]
            return create_response(result, fail_reasons=reasons, input_summary=summary, findings=findings)
        reasons = ["None of the seven ConnectWise apps has a service principal in this tenant."]
        return create_response(result, pass_reasons=reasons, input_summary=summary, findings=findings)
    except Exception as e:
        return not_measured("The Microsoft Graph feeds could not be read; exposure is not evaluated.",
                            transformation_errors=[str(e)])
