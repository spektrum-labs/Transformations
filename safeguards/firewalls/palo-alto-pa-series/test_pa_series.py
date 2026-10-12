"""Palo Alto Networks PA-Series firewall (PAN-OS XML API): fail-closed checks on synthetic bodies.

Bodies are SYNTHETIC and in the shape Integration-Service's xmltodict parse gives a PAN-OS XML
API response: {"response": {"@status": "success", "result": {...}}}. An error status, an
empty result, a refused or step-error body and an unrecognised body are all Not evaluated:
the key is None AND additionalInfo.dataCollection.status == "error". Never False, never 0.
Element names come from the public PAN-OS CLI/XML reference; shapes marked UNVERIFIED in each
transform are confirmed against one real read-only connection before go-live. No customer data.
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent

KEYS = [
    "firewallLoggingEnabled", "ipsEnabled", "isURLFilteringProfileEnabled", "wildfireInlineMlEnabled",
    "sslDeepInspectionEnabled", "isDosProtectionPolicyConfigured", "firmwareUpToDate",
    "isContentVersionCurrent", "autoUpdateSignaturesEnabled", "haModeEnabled", "vpnTunnelEstablished",
    "ipsecReplayProtectionEnabled", "isRulestackCommitClean", "adminLockoutThresholdCount",
    "restApiTokenExpiryEnforced", "isManagementInterfaceHttpsOnly", "restApiLoopbackRestricted",
]


MODULES = {}


def load(name):
    if name not in MODULES:
        spec = importlib.util.spec_from_file_location("pa_series_" + name, HERE / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        MODULES[name] = module
    return MODULES[name]


def run(name, body):
    out = load(name).transform(copy.deepcopy(body))
    return out


def value(name, body):
    return run(name, body)["transformedResponse"][name]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def assert_not_evaluated(name, body):
    out = run(name, body)
    assert out["transformedResponse"][name] is None, out["transformedResponse"]
    assert collection(out)["status"] == "error" and collection(out)["errors"]


# --- body builders ------------------------------------------------------------

def ok(result, code=None):
    response = {"@status": "success", "result": result}
    if code:
        response["@code"] = code
    return {"response": response}


def err(message="Unauthorized request", code="16"):
    return {"response": {"@status": "error", "@code": code, "msg": {"line": message}}}


def one_or_many(items):
    return items[0] if len(items) == 1 else items


def rules_body(rules):
    return ok({"@total-count": str(len(rules)), "@count": str(len(rules)), "rules": {"entry": one_or_many(rules)}})


def rule(name, action="allow", disabled=None, log_setting="fwd", log_end=None, apps=("any",),
         profiles=None, group=None):
    r = {"@name": name, "action": action, "application": {"member": one_or_many(list(apps))}}
    if disabled:
        r["disabled"] = disabled
    if log_setting:
        r["log-setting"] = log_setting
    if log_end:
        r["log-end"] = log_end
    if profiles:
        r["profile-setting"] = {"profiles": {k: {"member": v} for k, v in profiles.items()}}
    elif group:
        r["profile-setting"] = {"group": {"member": group}}
    return r


def groups_body(groups):
    """groups: {name: {kind: profile}}"""
    if not groups:
        return ok(None)
    entries = [dict({"@name": n}, **{k: {"member": v} for k, v in kinds.items()}) for n, kinds in groups.items()]
    return ok({"profile-group": {"entry": one_or_many(entries)}})


def policy(rules, groups=None, shared=None):
    return {"securityRules": rules_body(rules),
            "profileGroups": groups_body(groups or {}),
            "sharedProfileGroups": groups_body(shared or {})}


def sysinfo(**fields):
    base = {"hostname": "fw-test", "model": "PA-xxx", "sw-version": "10.2.7-h3"}
    base.update(fields)
    return ok({"system": base})


def stamp(days_ago):
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y/%m/%d 12:00:00 PDT")


def software_check(versions):
    return ok({"sw-updates": {"@last-updated-at": "2026/10/01 01:00:00", "msg": None,
                              "entry": [{"version": v, "filename": "PanOS_" + v, "current": "no", "latest": "no"}
                                        for v in versions]}})


# --- the shared fail-closed contract -------------------------------------------

NOT_EVALUATED_BODIES = {
    "empty_dict": {},
    "none": None,
    "empty_string": "",
    "unrelated": {"hello": "world"},
    "status_403": {"statusCode": 403, "error": "Forbidden"},
    "status_401_nested": {"error": {"statusCode": 401, "message": "Unauthorized"}},
    "vendor_error_as_response": {"vendorErrorAsResponse": {"status": 403, "errors": ["Forbidden"]}},
    "step_error": {"securityRules": {"stepError": True, "statusCode": 403, "errorSummary": "forbidden"}},
    "pan_error_status": err(),
    "pan_error_invalid_key": err("Invalid Credential", "403"),
    "pan_success_empty_result": ok(None),
    "pan_success_empty_object_not_present": ok(None, "7"),
}


# A successful PAN-OS reply with an empty result says the object is not in the configuration. For
# these three keys that is real evidence that nothing is configured (False); everywhere else it is
# not enough to answer. An empty body, an error or a refusal is Not evaluated for every key.
NOTHING_CONFIGURED_KEYS = {"sslDeepInspectionEnabled", "isDosProtectionPolicyConfigured", "restApiLoopbackRestricted"}
NOTHING_LABELS = {"pan_success_empty_result", "pan_success_empty_object_not_present"}
BATTERY = [(k, l) for k in KEYS for l in sorted(NOT_EVALUATED_BODIES)
           if not (k in NOTHING_CONFIGURED_KEYS and l in NOTHING_LABELS)]


@pytest.mark.parametrize("key,label", BATTERY)
def test_body_that_proves_nothing_is_not_evaluated(key, label):
    assert_not_evaluated(key, NOT_EVALUATED_BODIES[label])


@pytest.mark.parametrize("key", KEYS)
def test_json_string_body_is_decoded_not_ignored(key):
    # a str body must be read as JSON, not treated as an empty object, and an unusable one is Not evaluated
    assert_not_evaluated(key, json.dumps(err()))


def test_json_string_body_with_evidence_is_decoded():
    assert value("firewallLoggingEnabled", json.dumps(rules_body([rule("a")]))) is True
    assert value("isRulestackCommitClean", json.dumps(ok("no"))) is True


@pytest.mark.parametrize("key", KEYS)
def test_poisoned_body_is_not_evaluated(key):
    class Poison(dict):
        def get(self, *a, **k):
            raise RuntimeError("poisoned")

        def __getitem__(self, k):
            raise RuntimeError("poisoned")

        def __iter__(self):
            raise RuntimeError("poisoned")

        def items(self):
            raise RuntimeError("poisoned")

        def keys(self):
            raise RuntimeError("poisoned")

    out = load(key).transform(Poison(a=1))
    assert out["transformedResponse"][key] is None
    assert collection(out)["status"] == "error"


@pytest.mark.parametrize("key", KEYS)
def test_output_names_the_vendor_and_the_criterion(key):
    out = run(key, NOT_EVALUATED_BODIES["pan_error_status"])
    meta = out["additionalInfo"]["metadata"]
    assert meta["transformationId"] == key and meta["vendor"] == "Palo Alto Networks"


# --- firewallLoggingEnabled -----------------------------------------------------

def test_logging_true_when_every_enabled_rule_has_a_log_forwarding_profile():
    assert value("firewallLoggingEnabled", rules_body([rule("a"), rule("b", action="deny")])) is True


def test_logging_single_rule_as_dict():
    assert value("firewallLoggingEnabled", rules_body([rule("a")])) is True


def test_logging_false_when_an_enabled_rule_has_no_log_setting():
    assert value("firewallLoggingEnabled", rules_body([rule("a"), rule("b", log_setting=None)])) is False


def test_logging_false_when_log_at_session_end_is_off():
    assert value("firewallLoggingEnabled", rules_body([rule("a", log_end="no")])) is False


def test_logging_ignores_a_disabled_rule():
    assert value("firewallLoggingEnabled", rules_body([rule("a"), rule("b", disabled="yes", log_setting=None)])) is True


def test_logging_reads_the_rules_from_the_policy_workflow_shape_too():
    assert value("firewallLoggingEnabled", policy([rule("a", log_setting=None)])) is False


def test_logging_only_disabled_rules_is_not_evaluated():
    assert_not_evaluated("firewallLoggingEnabled", rules_body([rule("a", disabled="yes")]))


def test_logging_count_mismatch_is_possibly_truncated():
    body = rules_body([rule("a")])
    body["response"]["result"]["@total-count"] = "9"
    assert_not_evaluated("firewallLoggingEnabled", body)


# --- ipsEnabled / isURLFilteringProfileEnabled / wildfireInlineMlEnabled ---------

PROFILE_KEYS = [("ipsEnabled", "vulnerability")]


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_true_when_every_allow_rule_carries_it_directly(key, kind):
    assert value(key, policy([rule("a", profiles={kind: "p"}), rule("b", profiles={kind: "p"})])) is True


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_true_through_a_profile_group(key, kind):
    assert value(key, policy([rule("a", group="g1")], groups={"g1": {kind: "p"}})) is True


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_true_through_a_shared_profile_group(key, kind):
    assert value(key, policy([rule("a", group="g2")], shared={"g2": {kind: "p"}})) is True


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_false_when_an_allow_rule_has_none(key, kind):
    assert value(key, policy([rule("a", profiles={kind: "p"}), rule("b")])) is False


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_false_when_the_group_lacks_this_profile_kind(key, kind):
    assert value(key, policy([rule("a", group="g1")], groups={"g1": {"spyware": "p"}})) is False


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_ignores_deny_and_disabled_rules(key, kind):
    rules = [rule("a", profiles={kind: "p"}), rule("b", action="deny"), rule("c", disabled="yes")]
    assert value(key, policy(rules)) is True


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_unresolvable_group_is_not_evaluated(key, kind):
    body = policy([rule("a", group="missing")])
    assert_not_evaluated(key, body)


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_group_read_error_is_not_evaluated_unless_a_rule_already_fails(key, kind):
    body = policy([rule("a", group="g1")])
    body["profileGroups"] = err()
    assert_not_evaluated(key, body)
    body = policy([rule("a", group="g1"), rule("b")])
    body["profileGroups"] = err()
    assert value(key, body) is False


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_no_allow_rules_is_not_evaluated(key, kind):
    assert_not_evaluated(key, policy([rule("a", action="deny")]))


@pytest.mark.parametrize("key,kind", PROFILE_KEYS)
def test_profile_security_rules_missing_is_not_evaluated(key, kind):
    assert_not_evaluated(key, {"profileGroups": groups_body({})})


def test_url_filtering_true_when_every_web_capable_allow_rule_has_it():
    rules = [rule("web", apps=("web-browsing", "ssl"), profiles={"url-filtering": "p"}),
             rule("dns", apps=("dns",))]
    assert value("isURLFilteringProfileEnabled", policy(rules)) is True


def test_url_filtering_any_application_counts_as_web_capable():
    assert value("isURLFilteringProfileEnabled", policy([rule("a", apps=("any",))])) is False


def test_url_filtering_through_group():
    assert value("isURLFilteringProfileEnabled",
                 policy([rule("a", apps=("ssl",), group="g1")], groups={"g1": {"url-filtering": "p"}})) is True


def test_url_filtering_without_a_web_capable_rule_is_not_evaluated():
    assert_not_evaluated("isURLFilteringProfileEnabled", policy([rule("dns", apps=("dns",)), rule("ntp", apps=("ntp",))]))


# --- sslDeepInspectionEnabled -----------------------------------------------------

def decryption_body(rules):
    return ok({"rules": {"entry": one_or_many(rules)}})


def drule(name, action="decrypt", kind="ssl-forward-proxy", profile="dp", disabled=None, source=None,
          destination=None, category=None):
    r = {"@name": name, "action": action, "type": {kind: None}}
    if profile:
        r["profile"] = profile
    if disabled:
        r["disabled"] = disabled
    for field, listed in (("source", source), ("destination", destination), ("category", category)):
        if listed:
            r[field] = {"member": listed}
    return r


def test_decryption_true_with_an_enabled_forward_proxy_decrypt_rule_and_profile():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a"), drule("b", action="no-decrypt")])) is True


def test_decryption_false_when_only_no_decrypt_rules():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a", action="no-decrypt")])) is False


def test_decryption_false_when_only_ssh_proxy_or_inbound():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a", kind="ssh-proxy")])) is False


def test_decryption_false_when_the_forward_proxy_rule_has_no_decryption_profile():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a", profile=None)])) is False


def test_decryption_false_when_the_rule_is_disabled():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a", disabled="yes")])) is False


# --- isDosProtectionPolicyConfigured ------------------------------------------------

def dos_body(rules):
    return ok({"rules": {"entry": one_or_many(rules)}})


def dos_rule(name, action="protect", profile=True, disabled=None, source=None, destination=None):
    r = {"@name": name, "action": {action: None}}
    if source:
        r["source"] = {"member": source}
    if destination:
        r["destination"] = {"member": destination}
    if profile:
        r["protection"] = {"aggregate": {"profile": "dos-agg"}}
    if disabled:
        r["disabled"] = disabled
    return r


def test_dos_true_with_an_enabled_protect_rule_and_a_profile():
    assert value("isDosProtectionPolicyConfigured", dos_body([dos_rule("a")])) is True


def test_dos_classified_profile_counts():
    r = dos_rule("a", profile=False)
    r["protection"] = {"classified": {"profile": "dos-cls", "classification-criteria": {"address": "source-ip-only"}}}
    assert value("isDosProtectionPolicyConfigured", dos_body([r])) is True


def test_dos_false_when_rules_are_deny_or_allow_only():
    assert value("isDosProtectionPolicyConfigured", dos_body([dos_rule("a", action="deny", profile=False)])) is False


def test_dos_false_when_the_protect_rule_has_no_profile():
    assert value("isDosProtectionPolicyConfigured", dos_body([dos_rule("a", profile=False)])) is False


def test_dos_false_when_the_protect_rule_is_disabled():
    assert value("isDosProtectionPolicyConfigured", dos_body([dos_rule("a", disabled="yes")])) is False


# --- firmwareUpToDate ---------------------------------------------------------------

def firmware(installed, versions):
    return {"systemInfo": sysinfo(**{"sw-version": installed}), "softwareUpdates": software_check(versions)}


VERSIONS = ["10.2.7-h3", "10.2.9", "10.2.9-h1", "11.0.2", "10.1.14"]


def test_firmware_false_when_a_newer_release_exists_in_the_same_feature_train():
    assert value("firmwareUpToDate", firmware("10.2.7-h3", VERSIONS)) is False


def test_firmware_true_at_the_newest_release_of_its_train_including_hotfix():
    assert value("firmwareUpToDate", firmware("10.2.9-h1", VERSIONS)) is True


def test_firmware_false_on_the_base_release_when_its_hotfix_exists():
    assert value("firmwareUpToDate", firmware("10.2.9", VERSIONS)) is False


def test_firmware_a_newer_train_elsewhere_does_not_make_this_one_old():
    assert value("firmwareUpToDate", firmware("10.1.14", VERSIONS)) is True


def test_firmware_unparseable_installed_version_is_not_evaluated():
    assert_not_evaluated("firmwareUpToDate", firmware("not-a-version", VERSIONS))


def test_firmware_no_listed_release_in_its_train_is_not_evaluated():
    assert_not_evaluated("firmwareUpToDate", firmware("9.1.3", VERSIONS))


def test_firmware_software_check_error_is_not_evaluated():
    body = firmware("10.2.9-h1", VERSIONS)
    body["softwareUpdates"] = err("Could not reach the update server", "17")
    assert_not_evaluated("firmwareUpToDate", body)


def test_firmware_system_info_missing_is_not_evaluated():
    assert_not_evaluated("firmwareUpToDate", {"softwareUpdates": software_check(VERSIONS)})


# --- isContentVersionCurrent -----------------------------------------------------------

def content(app_days, av_days):
    f = {}
    if app_days is not None:
        f["app-version"] = "8900-8000"
        f["app-release-date"] = stamp(app_days)
    if av_days is not None:
        f["av-version"] = "5000-5500"
        f["av-release-date"] = stamp(av_days)
    return sysinfo(**f)


def test_content_true_when_apps_and_threats_and_antivirus_are_recent():
    assert value("isContentVersionCurrent", content(6, 1)) is True


def test_content_false_when_applications_and_threats_are_old():
    assert value("isContentVersionCurrent", content(90, 1)) is False


def test_content_false_when_antivirus_is_old():
    assert value("isContentVersionCurrent", content(3, 120)) is False


def test_content_missing_antivirus_date_is_not_evaluated():
    assert_not_evaluated("isContentVersionCurrent", content(3, None))


def test_content_unparseable_date_is_not_evaluated():
    assert_not_evaluated("isContentVersionCurrent", sysinfo(**{"app-release-date": "yesterday", "av-release-date": "today"}))


# --- autoUpdateSignaturesEnabled --------------------------------------------------------

def schedule(**sections):
    return ok({"update-schedule": sections})


def test_auto_update_true_when_threats_recurs_with_an_action():
    body = schedule(threats={"recurring": {"hourly": {"at": "5", "action": "download-and-install"}}})
    assert value("autoUpdateSignaturesEnabled", body) is True


def test_auto_update_download_only_is_false_because_nothing_is_installed():
    body = schedule(threats={"recurring": {"daily": {"at": "02:00", "action": "download-only"}}})
    out = run("autoUpdateSignaturesEnabled", body)
    assert out["transformedResponse"]["autoUpdateSignaturesEnabled"] is False
    assert collection(out)["status"] == "success"
    assert "not installed" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


def test_auto_update_false_when_threats_recurrence_is_none():
    assert value("autoUpdateSignaturesEnabled", schedule(threats={"recurring": {"none": None}})) is False


def test_auto_update_false_when_only_other_content_is_scheduled():
    body = schedule(**{"anti-virus": {"recurring": {"daily": {"at": "01:00", "action": "download-and-install"}}}})
    assert value("autoUpdateSignaturesEnabled", body) is False


def test_auto_update_schedule_without_an_action_is_not_evaluated():
    assert_not_evaluated("autoUpdateSignaturesEnabled", schedule(threats={"recurring": {"daily": {"at": "02:00"}}}))


# --- haModeEnabled ---------------------------------------------------------------------

def ha(enabled="yes", mode="Active-Passive", sync="synchronized"):
    result = {"enabled": enabled}
    if enabled == "yes":
        group = {"mode": mode, "local-info": {"state": "active"}, "peer-info": {"state": "passive", "conn-status": "up"}}
        if sync:
            group["running-sync"] = sync
        result["group"] = group
    return ok(result)


def test_ha_true_when_paired_and_synchronized():
    assert value("haModeEnabled", ha()) is True


def test_ha_active_active_counts():
    assert value("haModeEnabled", ha(mode="Active-Active")) is True


def test_ha_false_when_high_availability_is_not_enabled():
    assert value("haModeEnabled", ha(enabled="no")) is False


def test_ha_false_when_the_peer_is_not_synchronized():
    assert value("haModeEnabled", ha(sync="not synchronized")) is False


def test_ha_enabled_with_no_sync_state_is_not_evaluated():
    assert_not_evaluated("haModeEnabled", ha(sync=None))


# --- vpnTunnelEstablished ---------------------------------------------------------------

def vpn(*states):
    entries = [{"id": str(i + 1), "name": "tunnel-" + str(i + 1), "state": s} for i, s in enumerate(states)]
    return ok({"IPSec": {"entry": one_or_many(entries)}})


def test_vpn_true_when_every_tunnel_is_active():
    assert value("vpnTunnelEstablished", vpn("active", "active")) is True


def test_vpn_false_when_a_tunnel_is_in_init():
    assert value("vpnTunnelEstablished", vpn("active", "init")) is False


def test_vpn_single_tunnel_as_dict():
    assert value("vpnTunnelEstablished", vpn("active")) is True


def test_vpn_entry_without_a_state_is_not_evaluated():
    assert_not_evaluated("vpnTunnelEstablished", ok({"IPSec": {"entry": {"id": "1", "name": "t"}}}))


# --- ipsecReplayProtectionEnabled -------------------------------------------------------

def tunnels(*flags):
    entries = []
    for i, f in enumerate(flags):
        e = {"@name": "t" + str(i)}
        if f is not None:
            e["anti-replay"] = f
        entries.append(e)
    return ok({"ipsec": {"entry": one_or_many(entries)}})


def test_replay_true_when_every_tunnel_has_it_on():
    assert value("ipsecReplayProtectionEnabled", tunnels("yes", "yes")) is True


def test_replay_false_when_a_tunnel_turns_it_off():
    assert value("ipsecReplayProtectionEnabled", tunnels("yes", "no")) is False


def test_replay_unset_on_a_tunnel_is_not_evaluated():
    assert_not_evaluated("ipsecReplayProtectionEnabled", tunnels("yes", None))


def test_replay_an_off_tunnel_decides_even_when_another_is_unset():
    assert value("ipsecReplayProtectionEnabled", tunnels("no", None)) is False


# --- isRulestackCommitClean -------------------------------------------------------------

def test_commit_clean_true_when_no_pending_changes():
    assert value("isRulestackCommitClean", ok("no")) is True


def test_commit_clean_false_when_changes_are_pending():
    assert value("isRulestackCommitClean", ok("yes")) is False


def test_commit_clean_unexpected_text_is_not_evaluated():
    assert_not_evaluated("isRulestackCommitClean", ok("maybe"))


# --- adminLockoutThresholdCount --------------------------------------------------------

def mgmt(**parts):
    return ok(parts)


def test_lockout_reports_the_failed_attempt_count():
    assert value("adminLockoutThresholdCount", mgmt(**{"admin-lockout": {"failed-attempts": "5", "lockout-time": "30"}})) == 5


def test_lockout_zero_attempts_is_zero_not_none():
    out = value("adminLockoutThresholdCount", mgmt(**{"admin-lockout": {"failed-attempts": "0", "lockout-time": "0"}}))
    assert out == 0 and out is not False


def test_lockout_absent_setting_is_not_evaluated():
    assert_not_evaluated("adminLockoutThresholdCount", mgmt(**{"idle-timeout": "30"}))


def test_lockout_non_numeric_is_not_evaluated():
    assert_not_evaluated("adminLockoutThresholdCount", mgmt(**{"admin-lockout": {"failed-attempts": "many"}}))


# --- restApiTokenExpiryEnforced ---------------------------------------------------------

def test_api_key_lifetime_true_when_bounded():
    assert value("restApiTokenExpiryEnforced", mgmt(api={"key": {"lifetime": "1440"}})) is True


def test_api_key_lifetime_false_when_zero_never_expires():
    assert value("restApiTokenExpiryEnforced", mgmt(api={"key": {"lifetime": "0"}})) is False


def test_api_key_lifetime_absent_is_not_evaluated():
    assert_not_evaluated("restApiTokenExpiryEnforced", mgmt(**{"idle-timeout": "30"}))


# --- isManagementInterfaceHttpsOnly -----------------------------------------------------

def test_https_only_true_when_http_and_telnet_are_disabled():
    assert value("isManagementInterfaceHttpsOnly", ok({"service": {"disable-http": "yes", "disable-telnet": "yes"}})) is True


def test_https_only_false_when_http_is_enabled():
    assert value("isManagementInterfaceHttpsOnly", ok({"service": {"disable-http": "no", "disable-telnet": "yes"}})) is False


def test_https_only_false_when_telnet_is_enabled():
    assert value("isManagementInterfaceHttpsOnly", ok({"service": {"disable-http": "yes", "disable-telnet": "no"}})) is False


def test_https_only_unset_is_not_evaluated():
    assert_not_evaluated("isManagementInterfaceHttpsOnly", ok({"service": {"disable-ssh": "no"}}))


# --- restApiLoopbackRestricted ---------------------------------------------------------

def permitted(*names):
    return ok({"permitted-ip": {"entry": one_or_many([{"@name": n} for n in names])}})


def test_permitted_ip_true_with_specific_sources():
    assert value("restApiLoopbackRestricted", permitted("192.0.2.0/24", "198.51.100.7")) is True


def test_permitted_ip_false_when_any_source_is_listed():
    assert value("restApiLoopbackRestricted", permitted("192.0.2.0/24", "0.0.0.0/0")) is False


def test_permitted_ip_single_entry_as_dict():
    assert value("restApiLoopbackRestricted", permitted("192.0.2.9")) is True


# --- no customer or tenant data in the fixtures ------------------------------------------

def test_this_file_names_no_customer_host_or_address():
    text = pathlib.Path(__file__).read_text()
    assert ("10." + "30.") not in text and ("@spektrum" + ".ai") not in text


# --- review fixes (red first): scope, nothing configured, download-only, ML, discrimination --------

def test_programmatic_access_key_is_not_published_for_this_tool():
    # nothing the firewall can answer makes it False: a refused key is Not evaluated, so True would only
    # restate that our own call worked
    assert not (HERE / "isProgrammaticAccessEnabled.py").exists()


# sslDeepInspectionEnabled: scope and order matter, nothing configured is False
def test_decryption_false_when_the_only_decrypt_rule_covers_part_of_the_traffic():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a", source=["192.0.2.0/24"])])) is False


def test_decryption_false_when_a_scoped_category_is_the_only_coverage():
    assert value("sslDeepInspectionEnabled", decryption_body([drule("a", category=["streaming-media"])])) is False


def test_decryption_true_when_any_source_destination_and_category_are_listed():
    rule_all = drule("a", source=["any"], destination=["any"], category=["any"])
    assert value("sslDeepInspectionEnabled", decryption_body([rule_all])) is True


def test_decryption_false_when_a_no_decrypt_for_all_traffic_comes_first():
    rules = [drule("skip", action="no-decrypt"), drule("a")]
    assert value("sslDeepInspectionEnabled", decryption_body(rules)) is False


def test_decryption_true_when_a_narrow_no_decrypt_exception_comes_first():
    rules = [drule("skip", action="no-decrypt", category=["financial-services"]), drule("a")]
    assert value("sslDeepInspectionEnabled", decryption_body(rules)) is True


@pytest.mark.parametrize("body", [ok(None), ok(None, "7"), ok({"rules": None})])
def test_decryption_nothing_configured_on_a_successful_read_is_false(body):
    out = run("sslDeepInspectionEnabled", body)
    assert out["transformedResponse"]["sslDeepInspectionEnabled"] is False
    assert collection(out)["status"] == "success"


# isDosProtectionPolicyConfigured
def test_dos_false_when_the_only_protect_rule_covers_one_destination():
    assert value("isDosProtectionPolicyConfigured", dos_body([dos_rule("a", destination=["192.0.2.10"])])) is False


def test_dos_true_when_any_source_and_destination_are_listed():
    assert value("isDosProtectionPolicyConfigured", dos_body([dos_rule("a", source=["any"], destination=["any"])])) is True


@pytest.mark.parametrize("body", [ok(None), ok(None, "7"), ok({"rules": None})])
def test_dos_nothing_configured_on_a_successful_read_is_false(body):
    out = run("isDosProtectionPolicyConfigured", body)
    assert out["transformedResponse"]["isDosProtectionPolicyConfigured"] is False
    assert collection(out)["status"] == "success"


# restApiLoopbackRestricted
@pytest.mark.parametrize("body", [ok(None), ok(None, "7"), ok({"permitted-ip": None})])
def test_permitted_ip_empty_list_means_any_source_and_is_false(body):
    out = run("restApiLoopbackRestricted", body)
    assert out["transformedResponse"]["restApiLoopbackRestricted"] is False
    assert collection(out)["status"] == "success"
    assert "any source" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


def test_permitted_ip_two_halves_of_the_address_space_are_open():
    assert value("restApiLoopbackRestricted", permitted("0.0.0.0/1", "128.0.0.0/1")) is False


def test_permitted_ip_a_very_wide_prefix_is_open():
    assert value("restApiLoopbackRestricted", permitted("192.0.2.0/24", "10.0.0.0/7")) is False


def test_permitted_ip_a_slash_eight_is_not_treated_as_open():
    assert value("restApiLoopbackRestricted", permitted("10.0.0.0/8")) is True


# autoUpdateSignaturesEnabled
def test_auto_update_download_and_install_on_any_cadence_wins_over_download_only():
    body = schedule(threats={"recurring": {"daily": {"at": "02:00", "action": "download-only"},
                                           "hourly": {"at": "5", "action": "download-and-install"}}})
    assert value("autoUpdateSignaturesEnabled", body) is True


# firmwareUpToDate: the release list can sit under a versions wrapper
def test_firmware_reads_the_release_list_under_a_versions_wrapper():
    body = firmware("10.2.7-h3", VERSIONS)
    entries_list = body["softwareUpdates"]["response"]["result"]["sw-updates"].pop("entry")
    body["softwareUpdates"]["response"]["result"]["sw-updates"]["versions"] = {"entry": entries_list}
    assert value("firmwareUpToDate", body) is False
    body["systemInfo"] = sysinfo(**{"sw-version": "10.2.9-h1"})
    assert value("firmwareUpToDate", body) is True


# isContentVersionCurrent: a future release date is not evidence
def test_content_future_dated_release_is_not_evaluated():
    assert_not_evaluated("isContentVersionCurrent", content(-5, 1))


# wildfireInlineMlEnabled reads the Antivirus ML engine setting, not the WildFire Analysis attachment
def virus_body(profiles):
    """profiles: {name: ml action or None (no ML element)}"""
    items = []
    for n, action in profiles.items():
        e = {"@name": n}
        if action:
            e["mlav-engine-filebased-enabled"] = {"entry": [{"@name": "Windows Executables", "mlav-policy-action": action}]}
        items.append(e)
    return ok({"virus": {"entry": one_or_many(items)}})


def ml_policy(rules, groups=None, shared=None, virus=None, shared_virus=None):
    body = policy(rules, groups, shared)
    body["virusProfiles"] = virus_body(virus or {})
    body["sharedVirusProfiles"] = virus_body(shared_virus or {})
    return body


def test_wildfire_ml_true_when_every_allow_rule_has_an_antivirus_profile_with_the_ml_engine_enabled():
    body = ml_policy([rule("a", profiles={"virus": "av1"}), rule("b", profiles={"virus": "av1"})], virus={"av1": "enable"})
    assert value("wildfireInlineMlEnabled", body) is True


def test_wildfire_ml_true_through_a_profile_group_and_a_shared_antivirus_profile():
    body = ml_policy([rule("a", group="g1")], groups={"g1": {"virus": "av2"}}, shared_virus={"av2": "enable"})
    assert value("wildfireInlineMlEnabled", body) is True


def test_wildfire_ml_false_when_the_profile_only_alerts():
    body = ml_policy([rule("a", profiles={"virus": "av1"})], virus={"av1": "alert-only"})
    assert value("wildfireInlineMlEnabled", body) is False


def test_wildfire_ml_false_when_the_ml_engine_is_disabled_or_absent():
    for action in ("disable", None):
        body = ml_policy([rule("a", profiles={"virus": "av1"})], virus={"av1": action})
        assert value("wildfireInlineMlEnabled", body) is False


def test_wildfire_ml_false_when_a_wildfire_analysis_profile_is_all_that_is_attached():
    body = ml_policy([rule("a", profiles={"wildfire-analysis": "wf"})])
    assert value("wildfireInlineMlEnabled", body) is False


def test_wildfire_ml_false_when_one_allow_rule_has_no_antivirus_profile():
    body = ml_policy([rule("a", profiles={"virus": "av1"}), rule("b")], virus={"av1": "enable"})
    assert value("wildfireInlineMlEnabled", body) is False


def test_wildfire_ml_profile_that_cannot_be_read_is_not_evaluated():
    assert_not_evaluated("wildfireInlineMlEnabled", ml_policy([rule("a", profiles={"virus": "default"})]))
    body = ml_policy([rule("a", profiles={"virus": "av1"})], virus={"av1": "enable"})
    body["virusProfiles"] = err()
    assert_not_evaluated("wildfireInlineMlEnabled", body)


def test_wildfire_ml_ignores_deny_and_disabled_rules_and_needs_an_allow_rule():
    body = ml_policy([rule("a", profiles={"virus": "av1"}), rule("b", action="deny"), rule("c", disabled="yes")], virus={"av1": "enable"})
    assert value("wildfireInlineMlEnabled", body) is True
    assert_not_evaluated("wildfireInlineMlEnabled", ml_policy([rule("a", action="deny")]))


# one True body and one False body for every key: the answer must depend on the evidence
DISCRIMINATES = {
    "firewallLoggingEnabled": (lambda: rules_body([rule("a")]), lambda: rules_body([rule("a", log_setting=None)])),
    "ipsEnabled": (lambda: policy([rule("a", profiles={"vulnerability": "p"})]), lambda: policy([rule("a")])),
    "isURLFilteringProfileEnabled": (lambda: policy([rule("a", profiles={"url-filtering": "p"})]), lambda: policy([rule("a")])),
    "wildfireInlineMlEnabled": (lambda: ml_policy([rule("a", profiles={"virus": "v"})], virus={"v": "enable"}),
                                lambda: ml_policy([rule("a", profiles={"virus": "v"})], virus={"v": "disable"})),
    "sslDeepInspectionEnabled": (lambda: decryption_body([drule("a")]), lambda: decryption_body([drule("a", source=["192.0.2.0/24"])])),
    "isDosProtectionPolicyConfigured": (lambda: dos_body([dos_rule("a")]), lambda: dos_body([dos_rule("a", destination=["192.0.2.10"])])),
    "firmwareUpToDate": (lambda: firmware("10.2.9-h1", VERSIONS), lambda: firmware("10.2.9", VERSIONS)),
    "isContentVersionCurrent": (lambda: content(3, 3), lambda: content(90, 3)),
    "autoUpdateSignaturesEnabled": (
        lambda: schedule(threats={"recurring": {"daily": {"at": "02:00", "action": "download-and-install"}}}),
        lambda: schedule(threats={"recurring": {"daily": {"at": "02:00", "action": "download-only"}}})),
    "haModeEnabled": (lambda: ha(), lambda: ha(enabled="no")),
    "vpnTunnelEstablished": (lambda: vpn("active"), lambda: vpn("init")),
    "ipsecReplayProtectionEnabled": (lambda: tunnels("yes"), lambda: tunnels("no")),
    "isRulestackCommitClean": (lambda: ok("no"), lambda: ok("yes")),
    "restApiTokenExpiryEnforced": (lambda: mgmt(api={"key": {"lifetime": "60"}}), lambda: mgmt(api={"key": {"lifetime": "0"}})),
    "isManagementInterfaceHttpsOnly": (lambda: ok({"service": {"disable-http": "yes", "disable-telnet": "yes"}}),
                                       lambda: ok({"service": {"disable-http": "no", "disable-telnet": "yes"}})),
    "restApiLoopbackRestricted": (lambda: permitted("192.0.2.0/24"), lambda: permitted("0.0.0.0/0")),
}


@pytest.mark.parametrize("key", sorted(DISCRIMINATES))
def test_each_key_can_be_true_and_can_be_false_on_evidence(key):
    good, bad = DISCRIMINATES[key]
    assert value(key, good()) is True
    assert value(key, bad()) is False


def test_lockout_threshold_is_a_count_that_differs_with_the_setting():
    five = value("adminLockoutThresholdCount", mgmt(**{"admin-lockout": {"failed-attempts": "5"}}))
    three = value("adminLockoutThresholdCount", mgmt(**{"admin-lockout": {"failed-attempts": "3"}}))
    assert (five, three) == (5, 3)


def test_every_published_key_has_a_discriminating_test_or_is_the_count():
    assert set(KEYS) - set(DISCRIMINATES) == {"adminLockoutThresholdCount"}
