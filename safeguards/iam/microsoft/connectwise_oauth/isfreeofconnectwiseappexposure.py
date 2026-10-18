"""
Transformation: isFreeOfConnectWiseAppExposure
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management

Threat: abuse of two ConnectWise multitenant OAuth apps (Microsoft Threat Intelligence and
Huntress, 16-17 Oct 2026). A threat actor used customers' existing consent to these apps to get
tokens in customer tenants, ran Graph reconnaissance and added credentials to service principals.
  ConnectWise Cloud Backup (formerly SkyKick Backup)   appId 506e08f9-6e9a-4da4-942b-a099a03644ae
  ConnectWise Cloud Management - MS Teams              appId 24205314-2b89-4e07-a2a4-579e898a5640

Criterion: True when the tenant's service-principal list was read and neither app has an enabled
service principal in it. False when either app is present and enabled (Exposed). A present but
disabled service principal cannot get tokens, so it reads True and is named in the pass reason.

Data source: Integration-Service workflow isFreeOfConnectWiseAppExposure, merged Graph reads:
  servicePrincipals         GET /v1.0/servicePrincipals?$filter=appId in (...)          (Application.Read.All or Directory.Read.All)
  cwBackupAppRoles          GET /v1.0/servicePrincipals(appId='506e...')/appRoleAssignments
  cwTeamsAppRoles           GET /v1.0/servicePrincipals(appId='2420...')/appRoleAssignments
  cwBackupDelegatedGrants   GET /v1.0/servicePrincipals(appId='506e...')/oauth2PermissionGrants   (optional)
  cwTeamsDelegatedGrants    GET /v1.0/servicePrincipals(appId='2420...')/oauth2PermissionGrants   (optional)
  roleAssignments           GET /v1.0/roleManagement/directory/roleAssignments           (RoleManagement.Read.Directory or Directory.Read.All)
  spSignInsByApp, spSignInsFromIndicatorIp, directoryAudits, securityAlerts  (see the sibling file)
Every step runs with continueOnError, so a refused read arrives as {"stepError": true, ...}.

Verdict fields (identical in both criterion files):
  connectWiseVerdict     Not evaluated | Not exposed | Exposed | Indicators found
  connectWiseRiskLevel   high (Directory.ReadWrite.All or a peer permission, or a privileged
                         directory role such as Global Administrator) | standard | unknown (a
                         grant feed for a present app could not be read) | none
Not evaluated (None and dataCollection.status "error"): the service-principal feed is missing,
refused, errored, paged or unrecognised. A failed read is never "not exposed".
"""
import json
from datetime import datetime

KEY = "isFreeOfConnectWiseAppExposure"
TRANSFORMATION_ID = "isfreeofconnectwiseappexposure"

# ---- shared helper block: start (identical in both criterion files; a test pins it)
CONNECTWISE_APPS = {
    "506e08f9-6e9a-4da4-942b-a099a03644ae": "ConnectWise Cloud Backup (formerly SkyKick Backup)",
    "24205314-2b89-4e07-a2a4-579e898a5640": "ConnectWise Cloud Management - MS Teams",
}
# Published indicators (Microsoft Threat Intelligence and Huntress, 16-17 Oct 2026). Data, not logic.
INDICATOR_IPS = ("144.172.64.128",)
INDICATOR_USER_AGENTS = ("python-urllib/3.12", "python-requests/2.31", "python-requests/2.34.2")
WINDOW_START = "2026-10-15T00:00:00"
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
}
WRAPPER_KEYS = ("apiResponse", "api_response", "response", "result", "Output")
# Display-name markers for the two apps. App-initiated audit entries often carry a null appId, and a deleted
# app's service principal id is no longer in the presence feed, so the initiator's name is the remaining link.
CONNECTWISE_NAME_MARKERS = ("connectwise cloud backup", "connectwise cloud management", "skykick")


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


def lower(value):
    return value.strip().lower() if isinstance(value, str) else ""


def norm_activity(value):
    text = lower(value)
    for dash in ("–", "—"):
        text = text.replace(dash, "-")
    return " ".join(text.split())


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
    """(records, state) for one merged Graph feed. state is ok, missing, error or paged; records is a
    list only when state is ok."""
    feed = data.get(key)
    if feed is None:
        return None, "missing"
    stats = data.get("paginationStats")
    if isinstance(stats, dict) and isinstance(stats.get(key), dict) and stats[key].get("paginationTruncated") is True:
        return None, "paged"
    if isinstance(feed, list):
        records = feed
    elif isinstance(feed, dict):
        if feed.get("stepError") or feed.get("error") or feed.get("errors"):
            return None, "error"
        if feed.get("@odata.nextLink"):
            return None, "paged"
        records = feed.get("value")
        if not isinstance(records, list):
            return None, "error"
    else:
        return None, "error"
    for record in records:
        if not isinstance(record, dict):
            return None, "error"
    return records, "ok"


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
        sp_id = lower(record.get("id"))
        if roles_state == "ok":
            for item in roles:
                if lower(item.get("principalId")) == sp_id and lower(item.get("roleDefinitionId")) in PRIVILEGED_ROLES:
                    high.append(name + " holds the directory role " + PRIVILEGED_ROLES[lower(item.get("roleDefinitionId"))])
        else:
            unknown_risk = True

    # Indicators of compromise since the window start.
    indicators = []
    by_app, by_app_state = read_feed(data, "spSignInsByApp")
    by_ip, by_ip_state = read_feed(data, "spSignInsFromIndicatorIp")
    feeds["spSignInsByApp"] = by_app_state
    feeds["spSignInsFromIndicatorIp"] = by_ip_state
    sign_ins = (by_app or []) + (by_ip or [])
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
        app_name = lower(app.get("displayName"))
        by_connectwise = lower(app.get("appId")) in CONNECTWISE_APPS or lower(app.get("servicePrincipalId")) in sp_ids
        for marker in CONNECTWISE_NAME_MARKERS:
            if marker in app_name:
                by_connectwise = True
        from_ioc_ip = lower(user.get("ipAddress")) in INDICATOR_IPS
        on_connectwise = False
        for target in item.get("targetResources") or []:
            if not isinstance(target, dict):
                continue
            target_name = lower(target.get("displayName"))
            if lower(target.get("id")) in sp_ids or "connectwise" in target_name or "skykick" in target_name:
                on_connectwise = True
        when = str(item.get("activityDateTime"))
        if by_connectwise:
            indicators.append("A ConnectWise app performed '" + activity + "' at " + when)
        elif from_ioc_ip:
            indicators.append("'" + activity + "' from the indicator IP address at " + when)
        elif on_connectwise and is_credential:
            indicators.append("Credentials changed on a ConnectWise service principal ('" + activity + "') at " + when)
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
    indicators_read = by_app_state == "ok" and by_ip_state == "ok" and audits_state == "ok"

    if indicators:
        verdict = "Indicators found"
    elif not presence_known:
        verdict = "Not evaluated"
    elif enabled:
        verdict = "Exposed"
    else:
        verdict = "Not exposed"
    if not enabled:
        risk = "none" if presence_known else "unknown"
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
        "presenceKnown": presence_known, "present": present, "enabled": enabled, "names": names,
        "high": high, "risk": risk, "indicators": indicators, "indicatorsRead": indicators_read,
        "alertsState": alerts_state, "verdict": verdict, "feeds": feeds,
    }


def summary_fields(found):
    return {
        "connectWiseVerdict": found["verdict"],
        "connectWiseRiskLevel": found["risk"],
        "connectWiseAppsPresent": found["names"],
        "indicatorsFound": len(found["indicators"]),
    }


def not_measured(reason, found=None, transformation_errors=None):
    result = {KEY: None}
    if found is not None:
        result.update(summary_fields(found))
    else:
        result.update({"connectWiseVerdict": "Not evaluated", "connectWiseRiskLevel": "unknown",
                       "connectWiseAppsPresent": [], "indicatorsFound": 0})
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
        result = {KEY: not found["enabled"]}
        result.update(summary_fields(found))
        summary = {"feeds": found["feeds"]}
        findings = found["indicators"] + found["high"]
        if found["enabled"]:
            reasons = ["Enabled in this tenant: " + ", ".join(found["names"])]
            reasons = reasons + found["high"]
            if found["risk"] == "unknown":
                reasons.append("The app's permissions or directory roles could not be read; risk level unknown.")
            return create_response(result, fail_reasons=reasons, input_summary=summary, findings=findings)
        reasons = ["Neither ConnectWise app has an enabled service principal in this tenant."]
        if found["present"]:
            reasons.append("Present but disabled: " + ", ".join(found["names"]))
        return create_response(result, pass_reasons=reasons, input_summary=summary, findings=findings)
    except Exception as e:
        return not_measured("The Microsoft Graph feeds could not be read; exposure is not evaluated.",
                            transformation_errors=[str(e)])
