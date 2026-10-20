"""ConnectWise multitenant OAuth app abuse (October 2026): exposure and indicator checks.

The contract these tests pin:
- the presence read and the apps' sign-ins decide exposure: a present app, or one that signed in since
  13 Oct (as itself or for a user), is Exposed; a missing, refused, errored, paged or unrecognised
  service-principal feed, or an app sign-in read that is not whole inside log retention, is Not
  evaluated (None AND dataCollection.status "error"), never "not exposed";
- Integration-Service #1798 day-slices the directory audit log and the apps' delegated sign-ins: every
  slice key must be present and whole (paginationStats false), and each log's retention proof must show
  an entry at or before 13 Oct; otherwise the clean answer is Not evaluated, while evidence in any slice
  still counts. The old unsliced directoryAudits key is read under the same rules;
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
from datetime import date, timedelta

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


def slice_suffixes():
    """Integration-Service #1798: one bounded slice per UTC day from 15 Oct to 13 Nov 2026, then one from 14 Nov."""
    days = [date(2026, 10, 15) + timedelta(days=n) for n in range(30)]
    return [day.strftime("%Y%m%d") for day in days] + ["from20261114"]


AUDIT_KEYS = tuple("directoryAudits_" + suffix for suffix in slice_suffixes())
USER_KEYS = tuple("userSignInsByApp_" + suffix for suffix in slice_suffixes())
AUDIT_DAY = "directoryAudits_20261015"
USER_DAY = "userSignInsByApp_20261016"
AUDIT_PROBE = "directoryAuditsBeforeWindow"
USER_PROBE = "userSignInsBeforeWindow"


def retained():
    """Retention proofs whose newest entry at or before the start of the reads is older than 13 Oct 2026."""
    return {USER_PROBE: graph({"id": "probe-sign-in", "createdDateTime": "2026-10-12T23:40:00Z"}),
            AUDIT_PROBE: graph({"id": "probe-audit", "activityDateTime": "2026-10-12T21:05:00.1234567Z"})}


def audits(*entries):
    """Directory audit records in one day slice (the body keeps every other slice whole and empty)."""
    return {AUDIT_DAY: list(entries)}


def clean(**overrides):
    """A tenant where every app is absent and every feed and slice read whole with nothing in it, both logs shown
    to reach back before 13 Oct. paginationStats in overrides is merged into the slices' entries."""
    stats = {}
    body = {
        "servicePrincipals": graph(),
        "cwBackupAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "cwTeamsAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        # the five other Cloud Management apps (scope: 7 apps), absent: 404 as the reads report it
        "cwMgmtAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "cwExchangeAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "cwGraphAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "cwPartnerCenterAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "cwSharePointAppRoles": {"stepError": True, "statusCode": 404, "errorSummary": "Resource does not exist"},
        "roleAssignments": graph(role_assignment(OTHER_SP, GLOBAL_ADMIN)),
        "spSignInsByApp": graph(),
        "spSignInsFromIndicatorIp": graph(),
        "userSignInsFromIndicatorIp": graph(),
    }
    for key in AUDIT_KEYS + USER_KEYS:
        body[key] = []
        stats[key] = {"paginationTruncated": False}
    body[AUDIT_DAY] = [audit("Add service principal credentials", OTHER_SP)]
    body.update(retained())
    stats.update(overrides.pop("paginationStats", {}))
    body["paginationStats"] = stats
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
    body = exposed_backup(**audits(audit("Add service principal credentials", BACKUP_SP)))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_credentials_added_to_another_app_by_a_connectwise_app_is_an_indicator():
    activity = "Update application – Certificates and secrets management "
    body = exposed_backup(**audits(audit(activity, OTHER_SP, by_app=TEAMS_APP)))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_role_added_by_connectwise_service_principal_is_an_indicator():
    entry = audit("Add member to role", TEAMS_SP, by_sp=TEAMS_SP)
    entry["category"] = "RoleManagement"
    body = clean(servicePrincipals=graph(sp(TEAMS_APP, TEAMS_SP)), cwTeamsAppRoles=graph(), **audits(entry))
    _, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_audit_by_a_removed_connectwise_app_named_only_by_display_name_is_an_indicator():
    # App-initiated audit entries often carry initiatedBy.app.appId null and only the service principal id
    # and display name. Once the customer deletes the app, that id is no longer in the presence feed.
    removed_sp = "11111111-aaaa-4aaa-8aaa-000000000009"
    entry = audit("Add service principal credentials", OTHER_SP, by_sp=removed_sp)
    entry["initiatedBy"]["app"]["displayName"] = "ConnectWise Cloud Backup"
    _, indicators = run_both(clean(**audits(entry)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert value(indicators, "nameOnlyMatches") == 1


def test_audit_by_an_unrelated_app_with_a_similar_vendor_name_is_not_an_indicator():
    entry = audit("Add service principal credentials", OTHER_SP, by_sp="11111111-aaaa-4aaa-8aaa-000000000009")
    entry["initiatedBy"]["app"]["displayName"] = "ConnectWise Automate"
    _, indicators = run_both(clean(**audits(entry)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


def test_indicator_found_even_when_the_app_was_already_removed():
    # The app's own sign-in in the window is also exposure evidence (Integration-Service #1798), so a removed app
    # that signed in since 13 Oct is Exposed (risk unknown), not free of exposure.
    body = clean(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)))
    exposure, indicators = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseVerdict") == "Indicators found"
    assert value(exposure, "connectWiseAppsSignedIn") == ["ConnectWise Cloud Backup (formerly SkyKick Backup)"]
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    # an indicator from another app (not a ConnectWise sign-in) leaves exposure clean
    other = clean(userSignInsFromIndicatorIp=graph(sign_in("de8bc8b5-d9f9-48b1-a8ad-b748da725064", IOC_IP,
                                                           kind="interactiveUser")))
    exposure, _ = run_both(other)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is True
    assert value(exposure, "connectWiseVerdict") == "Indicators found"


def test_unreadable_sign_ins_leave_indicators_not_evaluated():
    for broken in (STEP_403, {"value": [], "@odata.nextLink": "https://graph.example/next"}, None):
        body = exposed_backup(spSignInsByApp=broken)
        if broken is None:
            del body["spSignInsByApp"]
        _, indicators = run_both(body)
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_unreadable_audits_leave_indicators_not_evaluated():
    _, indicators = run_both(exposed_backup(**{AUDIT_DAY: STEP_403}))
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")


def test_an_indicator_in_a_readable_feed_counts_when_another_feed_failed():
    body = exposed_backup(spSignInsByApp=STEP_403, **audits(audit("Add service principal credentials", BACKUP_SP)))
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
    not_evaluated = exposed_backup(securityAlerts=STEP_403, **{AUDIT_DAY: STEP_403})
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
              exposed_backup(**{AUDIT_DAY: STEP_403}),
              clean(**audits(audit("Add service principal credentials", OTHER_SP,
                                                target_name="SkyKick Backup")))] + NO_EVIDENCE
    for body in bodies:
        exposure, indicators = run_both(body)
        for key in ("connectWiseVerdict", "connectWiseRiskLevel", "connectWiseAppsPresent", "connectWiseAppsSignedIn",
                    "indicatorsFound", "nameOnlyMatches"):
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
        # window start 13 Oct 2026: 11 Nov is day 29 (inside 30-day retention), 12 Nov is day 30 (outside)
        at(11)
        _, indicators = run_both(exposed_backup())
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True
        at(12)
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
    body = exposed_backup(**audits(audit("Add service principal credentials", BACKUP_SP)),
                          paginationStats={AUDIT_DAY: {"paginationTruncated": True}})
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
                 **audits(audit("Add member to role", OTHER_SP, by_sp=BACKUP_SP)))
    exposure, indicators = run_both(body)
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    # the app's sign-in is exposure evidence even though the presence read failed
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseRiskLevel") == "unknown"
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
            exposure, indicators = run_both(clean(**audits(entry)))
            assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True, name
            assert value(exposure, "connectWiseVerdict") == "Not exposed", name
            assert value(indicators, "nameOnlyMatches") == 0, name


def test_published_names_match_exactly_after_normalising_and_are_tagged_name_only():
    variants = ("ConnectWise Cloud Backup", "connectwise  cloud backup", "SkyKick Backup", "SKYKICK CLOUD BACKUP",
                "ConnectWise Cloud Management - MS Teams", "ConnectWise Cloud Management – MS Teams",
                "ConnectWise Cloud Management-MS Teams", "SkyKick Cloud Manager - MS Teams", " SkyKick Backup ")
    for name in variants:
        for entry in (by_named_app(name), on_named_app(name)):
            exposure, indicators = run_both(clean(**audits(entry)))
            assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False, name
            for out in (exposure, indicators):
                assert value(out, "connectWiseVerdict") == "Indicators found", name
                assert value(out, "indicatorsFound") == 1 and value(out, "nameOnlyMatches") == 1, name
            text = reasons(indicators).lower()
            assert "name only" in text and "confirm" in text and "before any action" in text, name


def test_name_only_change_that_is_not_a_credential_change_on_a_named_target_is_not_an_indicator():
    # A role or grant change whose only link is a target named like the app is not one of the published
    # indicators (the old code did not flag it either); only credential changes on it are.
    _, indicators = run_both(clean(**audits(on_named_app("ConnectWise Cloud Backup", "Add member to role"))))
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
                     cwTeamsDelegatedGrants=graph(), **audits(entry))
        exposure, indicators = run_both(body)
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
        assert value(indicators, "nameOnlyMatches") == 0 and value(exposure, "nameOnlyMatches") == 0
        assert message in reasons(indicators)
        assert "name only" not in reasons(indicators).lower()


def test_name_only_and_id_matches_are_counted_apart():
    body = clean(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)),
                 **audits(by_named_app("SkyKick Backup")))
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


# ---- scope: 7 ConnectWise apps (J.J. 18 Oct). App ids and names as published by Huntress and BleepingComputer.

NEW_APPS = {
    "2399d300-6fca-4e6a-a686-399fefe75b83": ("ConnectWise Cloud Management", "cwMgmtAppRoles", "cwMgmtDelegatedGrants"),
    "b78f6a77-d4e5-46fb-87e5-d1648bd02519": ("ConnectWise Cloud Management - Exchange Online", "cwExchangeAppRoles",
                                             "cwExchangeDelegatedGrants"),
    "0de14c77-b9b0-4137-9360-34878a929827": ("ConnectWise Cloud Management - MS Graph", "cwGraphAppRoles",
                                             "cwGraphDelegatedGrants"),
    "412dcf96-176d-4b3a-a1b0-4981ad66971e": ("ConnectWise Cloud Management - Partner Center", "cwPartnerCenterAppRoles",
                                             "cwPartnerCenterDelegatedGrants"),
    "b2b55f5b-7758-4719-8d8f-88ae172e6bdb": ("ConnectWise Cloud Management - SharePoint Online", "cwSharePointAppRoles",
                                             "cwSharePointDelegatedGrants"),
}
NEW_SP = "11111111-aaaa-4aaa-8aaa-000000000020"


def new_app_body(app_id, enabled=True, roles=None, **overrides):
    name, role_feed, grant_feed = NEW_APPS[app_id]
    body = clean(servicePrincipals=graph(sp(app_id, NEW_SP, enabled=enabled, name=name)))
    body[role_feed] = graph(*(roles or []))
    body[grant_feed] = graph()
    body.update(overrides)
    return body


@pytest.mark.parametrize("app_id", list(NEW_APPS))
def test_each_new_app_present_is_exposed_at_standard_risk(app_id):
    exposure, indicators = run_both(new_app_body(app_id))
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    for out in (exposure, indicators):
        assert value(out, "connectWiseVerdict") == "Exposed" and value(out, "connectWiseRiskLevel") == "standard"
        assert value(out, "connectWiseAppsPresent") == [NEW_APPS[app_id][0]]
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True


@pytest.mark.parametrize("app_id", list(NEW_APPS))
def test_each_new_app_disabled_is_exposed_at_low_risk(app_id):
    exposure, _ = run_both(new_app_body(app_id, enabled=False))
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseRiskLevel") == "low"
    assert value(exposure, "connectWiseAppsPresent") == [NEW_APPS[app_id][0] + " (disabled)"]


@pytest.mark.parametrize("app_id", list(NEW_APPS))
def test_each_new_app_with_a_dangerous_permission_or_role_is_high_risk(app_id):
    exposure, _ = run_both(new_app_body(app_id, roles=[app_role(DIRECTORY_READWRITE_ALL)]))
    assert value(exposure, "connectWiseRiskLevel") == "high"
    exposure, _ = run_both(new_app_body(app_id, roleAssignments=graph(role_assignment(NEW_SP, GLOBAL_ADMIN))))
    assert value(exposure, "connectWiseRiskLevel") == "high"


@pytest.mark.parametrize("app_id", list(NEW_APPS))
def test_new_app_unreadable_grants_leave_risk_unknown(app_id):
    body = new_app_body(app_id)
    body[NEW_APPS[app_id][2]] = STEP_403
    exposure, _ = run_both(body)
    assert value(exposure, "connectWiseRiskLevel") == "unknown"


@pytest.mark.parametrize("app_id", list(NEW_APPS))
def test_indicators_by_app_id_for_each_new_app(app_id):
    entry = audit("Add service principal credentials", OTHER_SP, by_app=app_id)
    _, indicators = run_both(clean(**audits(entry)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert value(indicators, "nameOnlyMatches") == 0
    hit = sign_in(app_id, "203.0.113.7", agent="python-requests/2.31.0", sp_id=NEW_SP)
    _, indicators = run_both(clean(spSignInsByApp=graph(hit)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert NEW_APPS[app_id][0] in reasons(indicators)
    # the app's own sign-ins teach its service principal id, so a later audit entry by that id matches
    later = audit("Add member to role", OTHER_SP, by_sp=NEW_SP)
    _, indicators = run_both(clean(spSignInsByApp=graph(sign_in(app_id, "203.0.113.7", sp_id=NEW_SP)),
                                   **audits(later)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    assert value(indicators, "nameOnlyMatches") == 0


@pytest.mark.parametrize("name", [v[0] for v in NEW_APPS.values()] + ["SkyKick Cloud Manager",
                                                                     "connectwise cloud management – ms graph"])
def test_name_only_for_each_new_app_is_tagged(name):
    for entry in (by_named_app(name), on_named_app(name)):
        _, indicators = run_both(clean(**audits(entry)))
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False, name
        assert value(indicators, "nameOnlyMatches") == 1, name


def test_reads_scoped_to_the_two_original_apps_never_read_as_clean():
    # The Integration-Service #1798 workflow reads only the two original apps. A body without the five new
    # apps' feeds cannot show those apps are absent, so it is Not evaluated, never Not exposed or clean.
    body = clean()
    for _, role_feed, _ in NEW_APPS.values():
        del body[role_feed]
    exposure, indicators = run_both(body)
    assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")
    assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
    assert "seven" in reasons(exposure) and value(exposure, "connectWiseVerdict") == "Not evaluated"
    # a present app is still Exposed, and an indicator still counts
    body["servicePrincipals"] = graph(sp(BACKUP_APP, BACKUP_SP))
    body.update(cwBackupAppRoles=graph(), cwBackupDelegatedGrants=graph(),
                spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)))
    exposure, indicators = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_seven_apps_are_covered_with_distinct_feeds():
    for module in (EXPOSURE, INDICATORS):
        assert set(module.CONNECTWISE_APPS) == {BACKUP_APP, TEAMS_APP} | set(NEW_APPS)
        assert set(module.APP_ROLE_FEEDS) == set(module.CONNECTWISE_APPS)
        feeds = [f for pair in module.APP_ROLE_FEEDS.values() for f in pair]
        assert len(set(feeds)) == 14
        for app_id, (name, role_feed, grant_feed) in NEW_APPS.items():
            assert module.CONNECTWISE_APPS[app_id] == name
            assert module.APP_ROLE_FEEDS[app_id] == (role_feed, grant_feed)


# ---- gate follow-ups on 54fbb18b: curl/7.88.1 user agent (Medium), window from 13 Oct (Low)

CURL = "curl/7.88.1"


def test_curl_user_agent_is_an_indicator_only_for_a_connectwise_app():
    for module in (EXPOSURE, INDICATORS):
        assert CURL in module.INDICATOR_USER_AGENTS
    for app_id in (BACKUP_APP, TEAMS_APP, "412dcf96-176d-4b3a-a1b0-4981ad66971e"):
        hit = sign_in(app_id, "203.0.113.7", agent="curl/7.88.1", sp_id=NEW_SP)
        exposure, indicators = run_both(clean(spSignInsByApp=graph(hit)))
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False, app_id
        assert value(exposure, "connectWiseVerdict") == "Indicators found"
        assert "indicator user agent curl/7.88.1" in reasons(indicators)
    # another app with that user agent, from an ordinary address, is not an indicator
    other = sign_in("de8bc8b5-d9f9-48b1-a8ad-b748da725064", "203.0.113.7", agent="curl/7.88.1")
    _, indicators = run_both(clean(spSignInsByApp=graph(other)))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is True
    # from the indicator IP it counts on its own, whatever the app or agent
    _, indicators = run_both(clean(userSignInsFromIndicatorIp=graph(sign_in("de8bc8b5-d9f9-48b1-a8ad-b748da725064", IOC_IP,
                                                                           agent="curl/7.88.1", kind="interactiveUser"))))
    assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False


def test_window_starts_13_oct_for_audit_changes_and_sign_ins():
    for module in (EXPOSURE, INDICATORS):
        assert module.WINDOW_START == "2026-10-13T00:00:00"
    for when, counts in (("2026-10-13T00:00:00Z", True), ("2026-10-14T08:00:00Z", True),
                         ("2026-10-12T23:59:59Z", False)):
        changed = audit("Add service principal credentials", OTHER_SP, when=when, by_app=BACKUP_APP)
        _, indicators = run_both(clean(**audits(changed)))
        assert (value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False) is counts, when
        role = audit("Add member to role", OTHER_SP, when=when, by_app=TEAMS_APP)
        _, indicators = run_both(clean(**audits(role)))
        assert (value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False) is counts, when
        ip_hit = sign_in(BACKUP_APP, IOC_IP, when=when)
        _, indicators = run_both(clean(spSignInsFromIndicatorIp=graph(ip_hit)))
        assert (value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False) is counts, when


def test_once_13_oct_is_past_retention_a_clean_read_is_never_clean():
    try:
        at(12)  # 12 Nov 2026: 13 Oct is 30 days back
        exposure, indicators = run_both(clean())
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
        text = reasons(indicators)
        assert "13 Oct 2026" in text and "retention" in text
        assert indicators["additionalInfo"]["transformation"]["inputSummary"]["feeds"]["logRetention"] != "ok"
        # exposure does not depend on the clock (its sign-in reads are gated by the retention proofs in the body),
        # and an indicator found still counts
        assert value(exposure, "isFreeOfConnectWiseAppExposure") is True
        _, indicators = run_both(clean(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP))))
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
    finally:
        reset_clock()


# ---- review Medium (fail-open): a clean indicator read also needs the presence read

UNREAD_PRESENCE = (
    STEP_403,
    {"value": [], "@odata.nextLink": "https://graph.example/next"},
    {"value": [{"displayName": "no app id here"}]},
    None,
)


def presence_unread_body(presence, **overrides):
    body = clean(servicePrincipals=presence, **overrides)
    if presence is None:
        del body["servicePrincipals"]
    return body


def test_credential_add_on_an_unknown_sp_is_not_clean_when_the_presence_read_failed():
    # The presence read is the only source of the apps' service-principal ids when they have no sign-ins.
    # Without it, a credential add on a ConnectWise SP with no published target name cannot be ruled out.
    target = UNKNOWN_SP
    for presence in UNREAD_PRESENCE:
        body = presence_unread_body(presence, **audits(
            audit("Add service principal credentials", target, target_name=None)))
        exposure, indicators = run_both(body)
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
        assert_not_measured(exposure, "isFreeOfConnectWiseAppExposure")
        assert value(indicators, "connectWiseVerdict") == "Not evaluated"
        assert "service-principal" in reasons(indicators), reasons(indicators)


def test_clean_logs_are_not_evaluated_when_the_presence_read_failed():
    for presence in UNREAD_PRESENCE:
        _, indicators = run_both(presence_unread_body(presence))
        assert_not_measured(indicators, "isFreeOfConnectWiseCompromiseIndicators")
        assert value(indicators, "connectWiseVerdict") == "Not evaluated"


def test_an_indicator_still_counts_when_the_presence_read_failed():
    for presence in UNREAD_PRESENCE:
        body = presence_unread_body(presence, spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP)))
        _, indicators = run_both(body)
        assert value(indicators, "isFreeOfConnectWiseCompromiseIndicators") is False
        assert_measured(indicators)


# ---- Integration-Service #1798: day-sliced audit and delegated sign-in reads, retention proofs

INDICATOR_KEY = "isFreeOfConnectWiseCompromiseIndicators"
EXPOSURE_KEY = "isFreeOfConnectWiseAppExposure"
DELEGATED = "de8bc8b5-d9f9-48b1-a8ad-b748da725064"  # an unrelated first-party client app id


def delegated_sign_in(app_id, ip="203.0.113.7", sign_in_id="si-delegated-1", when="2026-10-16T09:30:00Z", agent=""):
    return {"id": sign_in_id, "appId": app_id, "ipAddress": ip, "createdDateTime": when, "userAgent": agent,
            "isInteractive": False, "signInEventTypes": ["nonInteractiveUser"], "status": {"errorCode": 0},
            "userPrincipalName": "user@example.com"}


def capped(key):
    return {"paginationStats": {key: {"paginationTruncated": True}}, "paginationTruncated": True}


def test_slice_keys_are_the_31_keys_1798_writes():
    for module in (EXPOSURE, INDICATORS):
        assert tuple(module.AUDIT_SLICE_KEYS) == AUDIT_KEYS and tuple(module.USER_SLICE_KEYS) == USER_KEYS
    assert len(AUDIT_KEYS) == 31 and AUDIT_KEYS[0] == "directoryAudits_20261015"
    assert AUDIT_KEYS[29] == "directoryAudits_20261113" and AUDIT_KEYS[30] == "directoryAudits_from20261114"
    assert USER_KEYS[0] == "userSignInsByApp_20261015" and USER_KEYS[-1] == "userSignInsByApp_from20261114"


def test_whole_slices_with_retained_logs_read_clean():
    exposure, indicators = run_both(clean())
    assert value(exposure, EXPOSURE_KEY) is True and value(indicators, INDICATOR_KEY) is True
    assert value(exposure, "connectWiseAppsSignedIn") == []
    feeds = indicators["additionalInfo"]["transformation"]["inputSummary"]["feeds"]
    assert feeds["directoryAudits"] == "ok" and feeds["userSignInsByApp"] == "ok"
    assert feeds[USER_PROBE] == "ok" and feeds[AUDIT_PROBE] == "ok"


@pytest.mark.parametrize("key", [AUDIT_KEYS[0], AUDIT_KEYS[17], AUDIT_KEYS[-1]])
def test_a_missing_errored_or_capped_audit_slice_leaves_indicators_not_evaluated(key):
    missing = clean()
    del missing[key]
    unreported = clean()
    del unreported["paginationStats"][key]
    for body in (missing, clean(**{key: STEP_403}), clean(**{key: {"stepError": True, "statusCode": 500}}),
                 clean(**capped(key)), clean(**{key: {"value": [], "@odata.nextLink": "https://graph.example/n"}}),
                 unreported, clean(**{key: "not a list"})):
        exposure, indicators = run_both(body)
        assert_not_measured(indicators, INDICATOR_KEY)
        assert key in reasons(indicators), reasons(indicators)
        # the audit log is not an exposure source: the apps are still shown absent and unused
        assert value(exposure, EXPOSURE_KEY) is True
        assert value(exposure, "connectWiseVerdict") == "Not exposed"


@pytest.mark.parametrize("key", [USER_KEYS[0], USER_KEYS[9], USER_KEYS[-1]])
def test_a_missing_errored_or_capped_user_slice_is_not_evaluated_never_not_exposed(key):
    missing = clean()
    del missing[key]
    for body in (missing, clean(**{key: STEP_403}), clean(**capped(key)),
                 clean(**{key: {"value": [], "@odata.nextLink": "https://graph.example/n"}})):
        exposure, indicators = run_both(body)
        assert_not_measured(exposure, EXPOSURE_KEY)
        assert_not_measured(indicators, INDICATOR_KEY)
        for out in (exposure, indicators):
            assert value(out, "connectWiseVerdict") == "Not evaluated"
            assert value(out, "connectWiseRiskLevel") == "unknown"
        assert key in reasons(exposure), reasons(exposure)


def test_an_unexplained_top_level_truncation_makes_every_feed_partial():
    body = clean(paginationTruncated=True)
    exposure, indicators = run_both(body)
    assert_not_measured(exposure, EXPOSURE_KEY)
    assert_not_measured(indicators, INDICATOR_KEY)
    # explained by the optional alert feed: the slices are still whole
    body = clean(securityAlerts=graph(), **capped("securityAlerts"))
    exposure, indicators = run_both(body)
    assert value(exposure, EXPOSURE_KEY) is True and value(indicators, INDICATOR_KEY) is True


RETENTION_GAPS = (None, graph(), STEP_403, {"stepError": True, "statusCode": 500}, "garbage",
                  # what #1798's proof (at or before 15 Oct) returns for a tenant active on 14 Oct: no proof for 13 Oct
                  "inside")


def proof(kind, field, gap):
    if gap == "inside":
        return graph({"id": "probe-new", field: "2026-10-14T18:00:00Z"})
    return gap


@pytest.mark.parametrize("gap", RETENTION_GAPS)
def test_a_sign_in_retention_proof_that_is_missing_empty_refused_failed_or_too_new_is_not_evaluated(gap):
    body = clean(**{USER_PROBE: proof("user", "createdDateTime", gap)})
    if gap is None:
        del body[USER_PROBE]
    exposure, indicators = run_both(body)
    assert_not_measured(exposure, EXPOSURE_KEY)
    assert_not_measured(indicators, INDICATOR_KEY)
    assert USER_PROBE in reasons(indicators) and USER_PROBE in reasons(exposure)


@pytest.mark.parametrize("gap", RETENTION_GAPS)
def test_an_audit_retention_proof_that_is_missing_empty_refused_failed_or_too_new_is_not_evaluated(gap):
    body = clean(**{AUDIT_PROBE: proof("audit", "activityDateTime", gap)})
    if gap is None:
        del body[AUDIT_PROBE]
    exposure, indicators = run_both(body)
    assert_not_measured(indicators, INDICATOR_KEY)
    assert AUDIT_PROBE in reasons(indicators)
    assert value(exposure, EXPOSURE_KEY) is True


def test_the_sign_in_proof_gates_the_unsliced_service_principal_sign_in_feeds():
    # every sign-in feed whole and empty, but the log cannot be shown to reach back to the window: an empty
    # service-principal read could be a read past retention, so it proves nothing
    body = clean(**{USER_PROBE: graph()})
    for key in ("spSignInsByApp", "spSignInsFromIndicatorIp", "userSignInsFromIndicatorIp"):
        assert body[key] == graph()
    _, indicators = run_both(body)
    assert_not_measured(indicators, INDICATOR_KEY)
    # a proof entry exactly at the window start counts
    _, indicators = run_both(clean(**{USER_PROBE: graph({"id": "p", "createdDateTime": "2026-10-13T00:00:00Z"})}))
    assert value(indicators, INDICATOR_KEY) is True


def test_a_delegated_sign_in_by_an_app_from_an_ordinary_ip_is_exposed():
    # Graph logs a delegated token's use as a user sign-in whose appId is the client app (#1798). The app has no
    # service principal now, no indicator is in it, and it is still Exposed: it had access in the window.
    for app_id in (BACKUP_APP, TEAMS_APP, "412dcf96-176d-4b3a-a1b0-4981ad66971e"):
        body = clean(**{USER_DAY: [delegated_sign_in(app_id)]})
        exposure, indicators = run_both(body)
        assert value(exposure, EXPOSURE_KEY) is False, app_id
        assert_measured(exposure)
        for out in (exposure, indicators):
            assert value(out, "connectWiseVerdict") == "Exposed"
            assert value(out, "connectWiseRiskLevel") == "unknown"
            assert value(out, "connectWiseAppsPresent") == []
            assert len(value(out, "connectWiseAppsSignedIn")) == 1
        assert value(indicators, INDICATOR_KEY) is True
        assert "no service principal here now" in reasons(exposure)


def test_a_service_principal_sign_in_by_a_removed_app_is_exposed_the_same_way():
    body = clean(spSignInsByApp=graph(sign_in(TEAMS_APP, "203.0.113.7", sp_id=TEAMS_SP)))
    exposure, _ = run_both(body)
    assert value(exposure, EXPOSURE_KEY) is False
    assert value(exposure, "connectWiseAppsSignedIn") == ["ConnectWise Cloud Management - MS Teams"]


def test_a_delegated_sign_in_by_a_present_app_keeps_its_risk_and_names_the_use():
    body = exposed_backup(**{USER_DAY: [delegated_sign_in(BACKUP_APP)]})
    exposure, _ = run_both(body)
    assert value(exposure, "connectWiseRiskLevel") == "standard"
    assert "signed in to this tenant 1 time(s)" in reasons(exposure)
    assert "no service principal here now" not in reasons(exposure)


def test_a_delegated_sign_in_by_another_app_is_not_exposure():
    exposure, indicators = run_both(clean(**{USER_DAY: [delegated_sign_in(DELEGATED)]}))
    assert value(exposure, EXPOSURE_KEY) is True and value(indicators, INDICATOR_KEY) is True


def test_a_delegated_sign_in_with_an_indicator_is_an_indicator():
    by_ip = clean(**{USER_DAY: [delegated_sign_in(BACKUP_APP, ip=IOC_IP)]})
    by_agent = clean(**{USER_DAY: [delegated_sign_in(TEAMS_APP, agent="python-requests/2.34.2")]})
    for body in (by_ip, by_agent):
        exposure, indicators = run_both(body)
        assert value(indicators, INDICATOR_KEY) is False
        assert value(exposure, EXPOSURE_KEY) is False
        assert value(exposure, "connectWiseVerdict") == "Indicators found"


def test_evidence_in_a_partial_slice_still_counts():
    # an indicator in a capped audit slice, with another audit slice refused and the audit proof missing
    entry = audit("Add service principal credentials", OTHER_SP, by_app=BACKUP_APP, when="2026-10-21T03:00:00Z")
    entry["id"] = "audit-partial-1"
    body = clean(**{AUDIT_KEYS[6]: [entry], AUDIT_KEYS[7]: STEP_403})
    body.update(capped(AUDIT_KEYS[6]))
    body["paginationStats"] = dict(clean()["paginationStats"], **capped(AUDIT_KEYS[6])["paginationStats"])
    del body[AUDIT_PROBE]
    exposure, indicators = run_both(body)
    assert value(indicators, INDICATOR_KEY) is False
    assert_measured(indicators)
    assert value(exposure, "connectWiseVerdict") == "Indicators found"
    # a delegated sign-in in a capped user slice, the sign-in proof refused: still Exposed
    body = clean(**{USER_KEYS[3]: {"value": [delegated_sign_in(BACKUP_APP)], "@odata.nextLink": "https://graph.example/n"},
                    USER_PROBE: STEP_403})
    exposure, indicators = run_both(body)
    assert value(exposure, EXPOSURE_KEY) is False and value(exposure, "connectWiseVerdict") == "Exposed"
    assert_not_measured(indicators, INDICATOR_KEY)


def test_records_at_a_slice_boundary_are_counted_once():
    midnight = audit("Add service principal credentials", OTHER_SP, by_app=BACKUP_APP, when="2026-10-16T00:00:00Z")
    body = clean(**{AUDIT_KEYS[0]: [midnight], AUDIT_KEYS[1]: [dict(midnight)]})
    _, indicators = run_both(body)
    assert value(indicators, "indicatorsFound") == 1
    same = delegated_sign_in(TEAMS_APP, when="2026-10-17T00:00:00Z")
    exposure, _ = run_both(clean(**{USER_KEYS[1]: [same], USER_KEYS[2]: [dict(same)]}))
    assert "signed in to this tenant 1 time(s)" in reasons(exposure)
    # different ids are different records
    other = dict(same, id="si-delegated-2")
    exposure, _ = run_both(clean(**{USER_KEYS[1]: [same], USER_KEYS[2]: [other]}))
    assert "signed in to this tenant 2 time(s)" in reasons(exposure)


def test_extra_slices_with_the_prefix_are_read_under_the_same_rules():
    # a reader that also slices 13-14 Oct: an indicator there counts, and a refused extra slice is a gap
    entry = audit("Add member to role", OTHER_SP, by_app=TEAMS_APP, when="2026-10-13T08:00:00Z")
    entry["id"] = "audit-extra-1"
    body = clean(directoryAudits_20261013=[entry], paginationStats={"directoryAudits_20261013": {"paginationTruncated": False}})
    _, indicators = run_both(body)
    assert value(indicators, INDICATOR_KEY) is False
    body = clean(directoryAudits_20261014=STEP_403)
    _, indicators = run_both(body)
    assert_not_measured(indicators, INDICATOR_KEY)
    assert "directoryAudits_20261014" in reasons(indicators)
    body = clean(userSignInsByApp_20261014=[], paginationStats={"userSignInsByApp_20261014": {"paginationTruncated": False}})
    exposure, indicators = run_both(body)
    assert value(exposure, EXPOSURE_KEY) is True and value(indicators, INDICATOR_KEY) is True


def legacy_body(feed, stats=False, proofs=True, **overrides):
    """A response stored before the slicing: one directoryAudits feed, no audit slices."""
    body = clean(**overrides)
    for key in AUDIT_KEYS:
        del body[key]
        del body["paginationStats"][key]
    body["directoryAudits"] = feed
    if stats is not None:
        body["paginationStats"]["directoryAudits"] = {"paginationTruncated": stats}
    if not proofs:
        del body[AUDIT_PROBE]
    return body


def test_the_old_unsliced_audit_key_is_still_read_under_the_same_rules():
    exposure, indicators = run_both(legacy_body(graph(audit("Add service principal credentials", OTHER_SP))))
    assert value(indicators, INDICATOR_KEY) is True and value(exposure, EXPOSURE_KEY) is True
    for body in (legacy_body(graph(), stats=None), legacy_body(graph(), stats=True), legacy_body(STEP_403),
                 legacy_body({"value": [], "@odata.nextLink": "https://graph.example/n"}),
                 legacy_body(graph(), proofs=False)):
        _, indicators = run_both(body)
        assert_not_measured(indicators, INDICATOR_KEY)
    # evidence in it counts, even capped and without a proof
    hit = audit("Add service principal credentials", BACKUP_SP)
    _, indicators = run_both(legacy_body(graph(hit), stats=True, proofs=False,
                                         servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP))))
    assert value(indicators, INDICATOR_KEY) is False
    # neither audit source at all is missing, not clean
    body = legacy_body(graph())
    del body["directoryAudits"]
    _, indicators = run_both(body)
    assert_not_measured(indicators, INDICATOR_KEY)


def test_with_slices_present_the_old_key_adds_evidence_only():
    hit = audit("Add member to role", OTHER_SP, by_app=BACKUP_APP)
    _, indicators = run_both(clean(directoryAudits=graph(hit)))
    assert value(indicators, INDICATOR_KEY) is False
    # a refused old key beside whole slices does not make the sliced log partial
    _, indicators = run_both(clean(directoryAudits=STEP_403))
    assert value(indicators, INDICATOR_KEY) is True


def test_a_1798_two_app_body_is_never_clean():
    # #1798 today: two apps' per-app feeds only, and its proofs ask for the newest entry at or before 15 Oct
    body = clean(**{USER_PROBE: proof("user", "createdDateTime", "inside"),
                    AUDIT_PROBE: proof("audit", "activityDateTime", "inside")})
    for _, role_feed, _ in NEW_APPS.values():
        del body[role_feed]
    exposure, indicators = run_both(body)
    assert_not_measured(exposure, EXPOSURE_KEY)
    assert_not_measured(indicators, INDICATOR_KEY)


def test_both_files_agree_on_the_sliced_fixtures():
    bodies = [clean(**{USER_DAY: [delegated_sign_in(BACKUP_APP)]}), clean(**{AUDIT_KEYS[4]: STEP_403}),
              clean(**{USER_PROBE: graph()}), legacy_body(graph()), clean(paginationTruncated=True),
              clean(**{USER_DAY: [delegated_sign_in(TEAMS_APP, ip=IOC_IP)]})]
    for body in bodies:
        exposure, indicators = run_both(body)
        for key in ("connectWiseVerdict", "connectWiseRiskLevel", "connectWiseAppsPresent", "connectWiseAppsSignedIn",
                    "indicatorsFound", "nameOnlyMatches"):
            assert value(exposure, key) == value(indicators, key), (key, body)
