"""ConnectWise multitenant OAuth app abuse (October 2026): exposure and indicator checks.

The contract these tests pin:
- the presence read decides exposure; a missing, refused, errored, paged or unrecognised
  service-principal feed is Not evaluated (None AND dataCollection.status "error"), never
  "not exposed";
- a present and enabled ConnectWise service principal is Exposed; a high-risk grant
  (Directory.ReadWrite.All and peers, or a privileged directory role) raises the risk level;
  an unreadable grant feed for a present app leaves the risk level "unknown", never "standard";
- an indicator found in ANY readable feed is a measured "indicators found"; "no indicators"
  needs the sign-in feeds and the directory-audit feed read whole;
- the two criterion files share one helper block byte for byte and agree on every fixture.

Every payload is synthetic: made-up object ids and tenants. The two application ids, the
indicator IP address and the user agents are the vendor's and Microsoft's published values.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent

BACKUP_APP = "506e08f9-6e9a-4da4-942b-a099a03644ae"
TEAMS_APP = "24205314-2b89-4e07-a2a4-579e898a5640"
BACKUP_SP = "11111111-aaaa-4aaa-8aaa-000000000001"
TEAMS_SP = "11111111-aaaa-4aaa-8aaa-000000000002"
OTHER_SP = "11111111-aaaa-4aaa-8aaa-000000000003"
DIRECTORY_READWRITE_ALL = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
USER_READ_ALL = "df021288-bdef-4463-88db-98f22de89214"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
IOC_IP = "144.172.64.128"

FILES = {
    "isfreeofconnectwiseappexposure": "isFreeOfConnectWiseAppExposure",
    "isfreeofconnectwisecompromiseindicators": "isFreeOfConnectWiseCompromiseIndicators",
}


def load(name):
    spec = importlib.util.spec_from_file_location("cw_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXPOSURE = load("isfreeofconnectwiseappexposure")
INDICATORS = load("isfreeofconnectwisecompromiseindicators")


def graph(*records):
    return {"value": list(records)}


def sp(app_id, object_id, enabled=True, name="ConnectWise app"):
    return {"id": object_id, "appId": app_id, "displayName": name, "accountEnabled": enabled}


def app_role(role_id):
    return {"id": "assign-" + role_id[:8], "appRoleId": role_id, "resourceDisplayName": "Microsoft Graph"}


def role_assignment(principal_id, role_id):
    return {"id": "ra-" + principal_id[-4:], "principalId": principal_id, "roleDefinitionId": role_id,
            "principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": principal_id}}


def sign_in(app_id, ip, when="2026-10-15T09:00:00Z", agent="", sp_id=None, kind="servicePrincipal"):
    return {"id": "si-" + ip, "appId": app_id, "ipAddress": ip, "createdDateTime": when, "userAgent": agent,
            "servicePrincipalId": sp_id, "signInEventTypes": [kind], "status": {"errorCode": 0}}


def audit(activity, target_id, when="2026-10-15T10:00:00Z", by_app=None, by_sp=None, target_name="Some app"):
    initiated = {"app": {"appId": by_app, "servicePrincipalId": by_sp, "displayName": None}, "user": None}
    return {"id": "audit-" + target_id[-4:], "activityDisplayName": activity, "activityDateTime": when,
            "category": "ApplicationManagement", "initiatedBy": initiated,
            "targetResources": [{"id": target_id, "displayName": target_name, "type": "ServicePrincipal"}]}


STEP_403 = {"stepError": True, "statusCode": 403, "errorSummary": "Insufficient privileges to complete the operation."}


def clean(**overrides):
    """A tenant where both apps are absent and every feed read whole with nothing in it."""
    body = {
        "servicePrincipals": graph(),
        "cwBackupAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "cwTeamsAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "roleAssignments": graph(role_assignment(OTHER_SP, GLOBAL_ADMIN)),
        "spSignInsByApp": graph(),
        "spSignInsFromIndicatorIp": graph(),
        "userSignInsFromIndicatorIp": graph(),
        "directoryAudits": graph(audit("Add service principal credentials", OTHER_SP)),
    }
    body.update(overrides)
    return body


def exposed_backup(**overrides):
    body = clean(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP, name="ConnectWise Cloud Backup")),
                 cwBackupAppRoles=graph(app_role(USER_READ_ALL)), cwBackupDelegatedGrants=graph())
    body.update(overrides)
    return body


def run_both(body):
    return EXPOSURE.transform(body), INDICATORS.transform(body)


def value(out, key):
    return out["transformedResponse"][key]


def assert_not_measured(out, key):
    assert out["transformedResponse"][key] is None, out["transformedResponse"]
    collected = out["additionalInfo"]["dataCollection"]
    assert collected["status"] == "error" and collected["errors"], collected


def assert_measured(out):
    assert out["additionalInfo"]["dataCollection"]["status"] == "success", out["additionalInfo"]


NO_EVIDENCE = [
    None,
    {},
    "{}",
    "",
    [],
    {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
    {"status": 401, "message": "unauthorised"},
    {"hello": "world"},
    {"servicePrincipals": STEP_403},
    {"servicePrincipals": {"value": [{"displayName": "no app id here"}]}},
    {"servicePrincipals": {"value": "not a list"}},
]


def test_no_evidence_is_not_evaluated_in_both_files():
    for body in NO_EVIDENCE:
        exposure, indicators = run_both(body)
        assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
        assert value(exposure, "connectWiseVerdict") == "Not evaluated", (body, exposure["transformedResponse"])


def test_clean_tenant_is_not_exposed_and_free_of_indicators():
    exposure, indicators = run_both(clean())
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is True
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True
    assert_measured(exposure)
    assert_measured(indicators)
    assert value(exposure, "connectWiseVerdict") == "Not exposed"


def test_paged_presence_feed_is_not_evaluated_not_absent():
    body = clean(servicePrincipals={"value": [], "@odata.nextLink": "https://graph.example/next"})
    exposure, _ = run_both(body)
    assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")
    body = clean(servicePrincipals=graph(), paginationStats={"servicePrincipals": {"paginationTruncated": True}})
    exposure, _ = run_both(body)
    assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")


def test_presence_feed_that_ignored_the_filter_still_only_counts_connectwise_apps():
    body = clean(servicePrincipals=graph(sp("00000003-0000-0000-c000-000000000000", OTHER_SP, name="Microsoft Graph")))
    exposure, _ = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is True


def test_present_backup_app_is_exposed_at_standard_risk():
    exposure, indicators = run_both(exposed_backup())
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert_measured(exposure)
    assert value(exposure, "connectWiseVerdict") == "Exposed"
    assert value(exposure, "connectWiseRiskLevel") == "standard"
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


def test_directory_readwrite_all_makes_it_high_risk():
    exposure, _ = run_both(exposed_backup(cwBackupAppRoles=graph(app_role(USER_READ_ALL), app_role(DIRECTORY_READWRITE_ALL))))
    assert value(exposure, "connectWiseVerdict") == "Exposed"
    assert value(exposure, "connectWiseRiskLevel") == "high"
    reasons = " ".join(exposure["additionalInfo"]["evaluation"]["failReasons"])
    assert "Directory.ReadWrite.All" in reasons


def test_delegated_directory_readwrite_all_grant_is_high_risk():
    body = exposed_backup(cwBackupDelegatedGrants=graph({"clientId": BACKUP_SP, "consentType": "AllPrincipals",
                                                         "scope": "openid Directory.ReadWrite.All"}))
    exposure, _ = run_both(body)
    assert value(exposure, "connectWiseRiskLevel") == "high"


def test_teams_app_holding_global_admin_is_high_risk():
    body = clean(servicePrincipals=graph(sp(TEAMS_APP, TEAMS_SP, name="ConnectWise Cloud Management - MS Teams")),
                 cwTeamsAppRoles=graph(), cwTeamsDelegatedGrants=graph(),
                 roleAssignments=graph(role_assignment(TEAMS_SP, GLOBAL_ADMIN)))
    exposure, _ = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseRiskLevel") == "high"
    assert "Global Administrator" in " ".join(exposure["additionalInfo"]["evaluation"]["failReasons"])


def test_unreadable_grants_for_a_present_app_leave_risk_unknown():
    exposure, _ = run_both(exposed_backup(cwBackupAppRoles=STEP_403, roleAssignments=STEP_403))
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseRiskLevel") == "unknown"


def test_disabled_service_principal_is_exposed_at_low_risk_and_must_be_removed():
    # Decision 18 Oct: a present but disabled app can be re-enabled and keeps its consent, grants and
    # credentials, so it is Exposed at risk low, and the finding says to remove it.
    body = clean(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP, enabled=False)),
                 cwBackupAppRoles=graph(app_role(DIRECTORY_READWRITE_ALL)), cwBackupDelegatedGrants=graph())
    exposure, indicators = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert_measured(exposure)
    for out in (exposure, indicators):
        assert value(out, "connectWiseVerdict") == "Exposed"
        assert value(out, "connectWiseRiskLevel") == "low"
    failed = " ".join(exposure["additionalInfo"]["evaluation"]["failReasons"])
    assert "disabled" in failed and "remove" in failed.lower()
    assert "(disabled)" in value(exposure, "connectWiseAppsPresent")[0]


def test_one_enabled_and_one_disabled_app_keeps_the_enabled_risk():
    body = exposed_backup(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP), sp(TEAMS_APP, TEAMS_SP, enabled=False)))
    exposure, _ = run_both(body)
    assert value(exposure, "connectWiseVerdict") == "Exposed"
    assert value(exposure, "connectWiseRiskLevel") == "standard"


def test_absent_apps_are_still_not_exposed_with_risk_none():
    exposure, _ = run_both(clean())
    assert value(exposure, "connectWiseVerdict") == "Not exposed"
    assert value(exposure, "connectWiseRiskLevel") == "none"


def test_missing_enabled_flag_counts_as_enabled():
    record = sp(BACKUP_APP, BACKUP_SP)
    del record["accountEnabled"]
    exposure, _ = run_both(clean(servicePrincipals=graph(record)))
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False


def test_sign_in_from_indicator_ip_is_an_indicator():
    body = exposed_backup(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)))
    exposure, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert_measured(indicators)
    assert value(exposure, "connectWiseVerdict") == "Indicators found"
    assert value(indicators, "connectWiseVerdict") == "Indicators found"


def test_connectwise_sign_in_with_indicator_user_agent_is_an_indicator():
    body = exposed_backup(spSignInsByApp=graph(sign_in(BACKUP_APP, "203.0.113.7", agent="python-requests/2.31.0")))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_connectwise_sign_in_from_an_ordinary_ip_is_not_an_indicator():
    body = exposed_backup(spSignInsByApp=graph(sign_in(BACKUP_APP, "203.0.113.7", agent="")))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


def test_sign_in_before_the_window_is_not_an_indicator():
    body = exposed_backup(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP, when="2026-10-01T09:00:00Z")))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


def test_credential_added_to_connectwise_service_principal_is_an_indicator():
    body = exposed_backup(directoryAudits=graph(audit("Add service principal credentials", BACKUP_SP)))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_credentials_added_to_another_app_by_a_connectwise_app_is_an_indicator():
    activity = "Update application – Certificates and secrets management "
    body = exposed_backup(directoryAudits=graph(audit(activity, OTHER_SP, by_app=TEAMS_APP)))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_role_added_by_connectwise_service_principal_is_an_indicator():
    entry = audit("Add member to role", TEAMS_SP, by_sp=TEAMS_SP)
    entry["category"] = "RoleManagement"
    body = clean(servicePrincipals=graph(sp(TEAMS_APP, TEAMS_SP)), cwTeamsAppRoles=graph(), directoryAudits=graph(entry))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_audit_by_a_removed_connectwise_app_named_only_by_display_name_is_an_indicator():
    # App-initiated audit entries often carry initiatedBy.app.appId null and only the service principal id
    # and display name. Once the customer deletes the app, that id is no longer in the presence feed.
    removed_sp = "11111111-aaaa-4aaa-8aaa-000000000009"
    entry = audit("Add service principal credentials", OTHER_SP, by_sp=removed_sp)
    entry["initiatedBy"]["app"]["displayName"] = "ConnectWise Cloud Backup"
    _, indicators = run_both(clean(directoryAudits=graph(entry)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert value(indicators, "nameOnlyMatches") == 1


def test_audit_by_an_unrelated_app_with_a_similar_vendor_name_is_not_an_indicator():
    entry = audit("Add service principal credentials", OTHER_SP, by_sp="11111111-aaaa-4aaa-8aaa-000000000009")
    entry["initiatedBy"]["app"]["displayName"] = "ConnectWise Automate"
    _, indicators = run_both(clean(directoryAudits=graph(entry)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


def test_indicator_found_even_when_the_app_was_already_removed():
    body = clean(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)))
    exposure, indicators = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is True
    assert value(exposure, "connectWiseVerdict") == "Indicators found"
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_unreadable_sign_ins_leave_indicators_not_evaluated():
    for broken in (STEP_403, {"value": [], "@odata.nextLink": "https://graph.example/next"}, None):
        body = exposed_backup(spSignInsByApp=broken)
        if broken is None:
            del body["spSignInsByApp"]
        _, indicators = run_both(body)
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_unreadable_audits_leave_indicators_not_evaluated():
    _, indicators = run_both(exposed_backup(directoryAudits=STEP_403))
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_an_indicator_in_a_readable_feed_counts_when_another_feed_failed():
    body = exposed_backup(spSignInsByApp=STEP_403, directoryAudits=graph(audit("Add service principal credentials", BACKUP_SP)))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert_measured(indicators)


def test_defender_alert_titles():
    alert = {"id": "alert-1", "title": "Verified Threat Actor IP", "createdDateTime": "2026-10-15T11:00:00Z"}
    _, indicators = run_both(exposed_backup(securityAlerts=graph(alert)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False

    generic = {"id": "alert-2", "title": "Suspicious sign-in", "createdDateTime": "2026-10-15T11:00:00Z",
               "evidence": [{"ipAddress": "198.51.100.4"}]}
    _, indicators = run_both(exposed_backup(securityAlerts=graph(generic)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True

    generic["evidence"] = [{"ipAddress": IOC_IP}]
    _, indicators = run_both(exposed_backup(securityAlerts=graph(generic)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_unreadable_alerts_do_not_block_but_are_reported():
    _, indicators = run_both(exposed_backup(securityAlerts=STEP_403))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True
    passed = " ".join(indicators["additionalInfo"]["evaluation"]["passReasons"])
    assert "Defender alerts were not read" in passed


def test_unread_alerts_are_named_on_every_indicator_outcome():
    # Decision 18 Oct: alerts stay optional, but no finding may imply Defender was covered.
    found = exposed_backup(securityAlerts=STEP_403, spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)))
    not_evaluated = exposed_backup(securityAlerts=STEP_403, directoryAudits=STEP_403)
    for body in (found, not_evaluated):
        _, indicators = run_both(body)
        reasons = " ".join(indicators["additionalInfo"]["evaluation"]["failReasons"])
        assert "Defender alerts were not read" in reasons, indicators["additionalInfo"]["evaluation"]
    _, indicators = run_both(found)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert value(indicators, "indicatorsFound") == 1


def test_read_alerts_are_not_called_unread():
    _, indicators = run_both(exposed_backup(securityAlerts=graph()))
    evaluation = indicators["additionalInfo"]["evaluation"]
    assert "Defender alerts were not read" not in " ".join(evaluation["passReasons"] + evaluation["failReasons"])


def test_poisoned_body_is_not_evaluated():
    class Poison(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError("boom")

        def __getitem__(self, key):
            raise RuntimeError("boom")

    exposure, indicators = run_both(Poison(servicePrincipals=graph()))
    assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_wrapped_inputs_are_read():
    exposure, _ = run_both({"apiResponse": exposed_backup()})
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    exposure, _ = run_both({"data": exposed_backup(), "validation": {"status": "passed"}})
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    exposure, _ = run_both({"data": exposed_backup(), "validation": {"status": "failed"}})
    assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")


def test_both_files_agree_on_every_fixture():
    bodies = [clean(), exposed_backup(), exposed_backup(cwBackupAppRoles=graph(app_role(DIRECTORY_READWRITE_ALL))),
              clean(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP, enabled=False))),
              exposed_backup(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP))),
              exposed_backup(directoryAudits=STEP_403),
              clean(directoryAudits=graph(audit("Add service principal credentials", OTHER_SP,
                                                target_name="SkyKick Backup")))] + NO_EVIDENCE
    for body in bodies:
        exposure, indicators = run_both(body)
        for key in ("connectWiseVerdict", "connectWiseRiskLevel", "connectWiseAppsPresent", "indicatorsFound",
                    "nameOnlyMatches"):
            assert value(exposure, key) == value(indicators, key), (key, body)


def test_helper_block_is_identical_in_both_files():
    blocks = []
    for name in FILES:
        text = (HERE / (name + ".py")).read_text()
        start = text.index("# ---- shared helper block: start")
        end = text.index("# ---- shared helper block: end")
        blocks.append(text[start:end])
    assert blocks[0] == blocks[1]


# ---- gate follow-ups (17 Oct): M1 grant feed, M2 retention, M3 user sign-ins, paged and SP-id Lows

def at(module_day):
    """Pin the evaluation date in both files."""
    from datetime import datetime as _dt
    stamp = _dt(2026, 11, module_day) if isinstance(module_day, int) else module_day
    for module in (EXPOSURE, INDICATORS):
        module.today = lambda stamp=stamp: stamp


def reset_clock():
    for module in (EXPOSURE, INDICATORS):
        module.today = module.__dict__["utc_now"]


@pytest.fixture(autouse=True)
def _clock_inside_retention():
    """Every test runs on 1 Nov 2026, inside log retention, so the suite does not turn red on 14 Nov 2026
    when the real clock passes the retention window. The retention tests still pin their own dates."""
    at(1)
    yield
    reset_clock()


def test_clock_is_pinned_for_every_test():
    from datetime import datetime as _dt
    assert INDICATORS.today() == _dt(2026, 11, 1) and EXPOSURE.today() == _dt(2026, 11, 1)


def test_unreadable_delegated_grants_for_an_enabled_app_leave_risk_unknown():
    for broken in (STEP_403, None):
        body = exposed_backup(cwBackupDelegatedGrants=broken)
        if broken is None:
            del body["cwBackupDelegatedGrants"]
        exposure, _ = run_both(body)
        assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
        assert value(exposure, "connectWiseRiskLevel") == "unknown", broken


def test_clean_indicators_read_after_log_retention_passed_the_window_are_not_evaluated():
    try:
        at(13)
        _, indicators = run_both(exposed_backup())
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True
        at(15)
        exposure, indicators = run_both(exposed_backup())
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
        assert "retention" in " ".join(indicators["additionalInfo"]["evaluation"]["failReasons"])
        assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    finally:
        reset_clock()


def test_indicator_found_after_retention_still_counts():
    try:
        at(20)
        _, indicators = run_both(exposed_backup(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP))))
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    finally:
        reset_clock()


def test_user_sign_in_from_indicator_ip_is_an_indicator():
    hit = sign_in("de8bc8b5-d9f9-48b1-a8ad-b748da725064", IOC_IP, kind="nonInteractiveUser")
    _, indicators = run_both(exposed_backup(userSignInsFromIndicatorIp=graph(hit)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_unreadable_user_sign_ins_leave_indicators_not_evaluated():
    body = exposed_backup(userSignInsFromIndicatorIp=STEP_403)
    _, indicators = run_both(body)
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
    body = exposed_backup()
    del body["userSignInsFromIndicatorIp"]
    _, indicators = run_both(body)
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_indicator_on_a_paged_feed_still_counts():
    paged = {"value": [sign_in(BACKUP_APP, IOC_IP)], "@odata.nextLink": "https://graph.example/next"}
    exposure, indicators = run_both(exposed_backup(spSignInsFromIndicatorIp=paged))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert value(exposure, "connectWiseVerdict") == "Indicators found"
    body = exposed_backup(directoryAudits=graph(audit("Add service principal credentials", BACKUP_SP)),
                          paginationStats={"directoryAudits": {"paginationTruncated": True}})
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_clean_paged_feed_is_still_not_evaluated():
    paged = {"value": [], "@odata.nextLink": "https://graph.example/next"}
    _, indicators = run_both(exposed_backup(spSignInsFromIndicatorIp=paged))
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_audit_by_connectwise_sp_id_counts_when_the_presence_read_failed():
    # The SP id is learned from the app's own sign-ins, so the audit match does not need the presence feed.
    body = clean(servicePrincipals=STEP_403,
                 spSignInsByApp=graph(sign_in(BACKUP_APP, "203.0.113.7", sp_id=BACKUP_SP)),
                 directoryAudits=graph(audit("Add member to role", OTHER_SP, by_sp=BACKUP_SP)))
    exposure, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")
    assert value(exposure, "connectWiseVerdict") == "Indicators found"


# ---- name matching narrowed (18 Oct): exact published names only, name-only matches tagged

OTHER_VENDOR_APPS = ("ConnectWise Automate", "ConnectWise Manage", "ConnectWise ScreenConnect", "ScreenConnect",
                     "ConnectWise Control", "SkyKick Migration", "SkyKick", "ConnectWise",
                     "ConnectWise Cloud Backup Reporting")
UNKNOWN_SP = "11111111-aaaa-4aaa-8aaa-000000000009"


def by_named_app(name, activity="Add service principal credentials", target=OTHER_SP):
    entry = audit(activity, target, by_sp=UNKNOWN_SP)
    entry["initiatedBy"]["app"]["displayName"] = name
    return entry


def on_named_app(name, activity="Add service principal credentials"):
    return audit(activity, UNKNOWN_SP, target_name=name)


def reasons(out):
    return " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


def test_credential_changes_by_or_on_other_connectwise_and_skykick_apps_are_not_indicators():
    for name in OTHER_VENDOR_APPS:
        for entry in (by_named_app(name), on_named_app(name),
                      by_named_app(name, "Update application - Certificates and secrets management")):
            exposure, indicators = run_both(clean(directoryAudits=graph(entry)))
            assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True, name
            assert value(exposure, "connectWiseVerdict") == "Not exposed", name
            assert value(indicators, "nameOnlyMatches") == 0, name


def test_published_names_match_exactly_after_normalising_and_are_tagged_name_only():
    variants = ("ConnectWise Cloud Backup", "connectwise  cloud backup", "SkyKick Backup", "SKYKICK CLOUD BACKUP",
                "ConnectWise Cloud Management - MS Teams", "ConnectWise Cloud Management – MS Teams",
                "ConnectWise Cloud Management-MS Teams", "SkyKick Cloud Manager - MS Teams", " SkyKick Backup ")
    for name in variants:
        for entry in (by_named_app(name), on_named_app(name)):
            exposure, indicators = run_both(clean(directoryAudits=graph(entry)))
            assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False, name
            for out in (exposure, indicators):
                assert value(out, "connectWiseVerdict") == "Indicators found", name
                assert value(out, "indicatorsFound") == 1 and value(out, "nameOnlyMatches") == 1, name
            text = reasons(indicators).lower()
            assert "name only" in text and "confirm" in text and "before any action" in text, name


def test_name_only_change_that_is_not_a_credential_change_on_a_named_target_is_not_an_indicator():
    # A role or grant change whose only link is a target named like the app is not one of the published
    # indicators (the old code did not flag it either); only credential changes on it are.
    _, indicators = run_both(clean(directoryAudits=graph(on_named_app("ConnectWise Cloud Backup", "Add member to role"))))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


def test_id_matches_are_unchanged_and_never_tagged_name_only():
    by_id = audit("Add service principal credentials", OTHER_SP, by_app=TEAMS_APP)
    by_id["initiatedBy"]["app"]["displayName"] = "ConnectWise Cloud Management - MS Teams"
    by_unrelated_name = audit("Add member to role", OTHER_SP, by_sp=TEAMS_SP)
    by_unrelated_name["initiatedBy"]["app"]["displayName"] = "Renamed by the tenant"
    on_id = audit("Add service principal credentials", BACKUP_SP, target_name="Renamed by the tenant")
    for entry, message in ((by_id, "A ConnectWise app performed"),
                           (by_unrelated_name, "A ConnectWise app performed"),
                           (on_id, "Credentials changed on a ConnectWise service principal")):
        body = clean(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP), sp(TEAMS_APP, TEAMS_SP)),
                     cwBackupAppRoles=graph(), cwBackupDelegatedGrants=graph(), cwTeamsAppRoles=graph(),
                     cwTeamsDelegatedGrants=graph(), directoryAudits=graph(entry))
        exposure, indicators = run_both(body)
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
        assert value(indicators, "nameOnlyMatches") == 0 and value(exposure, "nameOnlyMatches") == 0
        assert message in reasons(indicators)
        assert "name only" not in reasons(indicators).lower()


def test_name_only_and_id_matches_are_counted_apart():
    body = clean(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)),
                 directoryAudits=graph(by_named_app("SkyKick Backup")))
    exposure, indicators = run_both(body)
    for out in (exposure, indicators):
        assert value(out, "indicatorsFound") == 2 and value(out, "nameOnlyMatches") == 1


def test_no_bare_vendor_substring_test_remains():
    for name in FILES:
        source = (HERE / (name + ".py")).read_text()
        assert "CONNECTWISE_NAME_MARKERS" not in source
        assert '"connectwise" in' not in source and '"skykick" in' not in source
        assert "for marker in CONNECTWISE" not in source


def test_clean_and_not_evaluated_outcomes_report_zero_name_only_matches():
    for body in (clean(), {"servicePrincipals": STEP_403}, None):
        for out in run_both(body):
            assert value(out, "nameOnlyMatches") == 0
