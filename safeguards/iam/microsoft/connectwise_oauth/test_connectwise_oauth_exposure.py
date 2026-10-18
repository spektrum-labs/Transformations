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


def sign_in(app_id, ip, when="2026-10-15T09:00:00Z", agent=""):
    return {"id": "si-" + ip, "appId": app_id, "ipAddress": ip, "createdDateTime": when, "userAgent": agent,
            "signInEventTypes": ["servicePrincipal"], "status": {"errorCode": 0}}


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
        "directoryAudits": graph(audit("Add service principal credentials", OTHER_SP)),
    }
    body.update(overrides)
    return body


def exposed_backup(**overrides):
    body = clean(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP, name="ConnectWise Cloud Backup")),
                 cwBackupAppRoles=graph(app_role(USER_READ_ALL)))
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
                 cwTeamsAppRoles=graph(),
                 roleAssignments=graph(role_assignment(TEAMS_SP, GLOBAL_ADMIN)))
    exposure, _ = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseRiskLevel") == "high"
    assert "Global Administrator" in " ".join(exposure["additionalInfo"]["evaluation"]["failReasons"])


def test_unreadable_grants_for_a_present_app_leave_risk_unknown():
    exposure, _ = run_both(exposed_backup(cwBackupAppRoles=STEP_403, roleAssignments=STEP_403))
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is False
    assert value(exposure, "connectWiseRiskLevel") == "unknown"


def test_disabled_service_principal_is_not_exposed_but_reported():
    body = clean(servicePrincipals=graph(sp(BACKUP_APP, BACKUP_SP, enabled=False)))
    exposure, _ = run_both(body)
    assert value(exposure, "isFreeOfConnectWiseAppExposure") is True
    assert value(exposure, "connectWiseVerdict") == "Not exposed"
    assert "disabled" in " ".join(exposure["additionalInfo"]["evaluation"]["passReasons"])


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
              exposed_backup(spSignInsFromIndicatorIp=graph(sign_in(BACKUP_APP, IOC_IP))),
              exposed_backup(directoryAudits=STEP_403)] + NO_EVIDENCE
    for body in bodies:
        exposure, indicators = run_both(body)
        for key in ("connectWiseVerdict", "connectWiseRiskLevel", "connectWiseAppsPresent", "indicatorsFound"):
            assert value(exposure, key) == value(indicators, key), (key, body)


def test_helper_block_is_identical_in_both_files():
    blocks = []
    for name in FILES:
        text = (HERE / (name + ".py")).read_text()
        start = text.index("# ---- shared helper block: start")
        end = text.index("# ---- shared helper block: end")
        blocks.append(text[start:end])
    assert blocks[0] == blocks[1]
