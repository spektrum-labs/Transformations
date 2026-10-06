"""Intune isPowerShellConstrainedLanguageEnforced (EP-004): fixtures follow Microsoft Graph shapes for
configurationPolicies with $expand=assignments,settings (settings-catalog setting instances) and
deviceConfigurations (windows10CustomConfiguration omaSettings for AppLocker). Names and ids are synthetic.
Cases run typed, stringified (as Token-Service stores it), wrapped, as a JSON string, and through the
RestrictedPython replica."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "ispowershellconstrainedlanguageenforced.py")
KEY = "isPowerShellConstrainedLanguageEnforced"
BUILT_IN = "device_vendor_msft_policy_config_applicationcontrol_built_in_controls"


def load_plain():
    spec = importlib.util.spec_from_file_location("intune_clm", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def value(body, loader=load_plain):
    out = loader()(body)
    return out["transformedResponse"][KEY], out


ALL_DEVICES = {"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget",
                          "deviceAndAppManagementAssignmentFilterType": "none"}}


def group(gid, exclude=False):
    kind = "exclusionGroupAssignmentTarget" if exclude else "groupAssignmentTarget"
    return {"target": {"@odata.type": "#microsoft.graph." + kind, "groupId": gid,
                       "deviceAndAppManagementAssignmentFilterType": "none"}}


def app_control(name, mode="enforce", assignments=None, family="endpointSecurityApplicationControl"):
    suffix = "_enable_app_control_0" if mode == "enforce" else "_enable_app_control_1"
    settings = [{"id": "0", "settingInstance": {
        "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
        "settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_policiesoptions",
        "groupSettingCollectionValue": [{"children": [{
            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
            "settingDefinitionId": BUILT_IN,
            "choiceSettingValue": {"value": BUILT_IN + "_enable_app_control" + suffix[len("_enable_app_control"):],
                                   "children": []}}]}]}}]
    return {"id": "p-" + name, "name": name, "platforms": "windows10",
            "templateReference": {"templateFamily": family, "templateId": "4321b946-b76b-4450-8afd-769c08b16ffc_1"},
            "settings": settings, "assignments": [ALL_DEVICES] if assignments is None else assignments}


def xml_policy(name, options, assignments=None, file_rules="<Allow ID=\"ID_ALLOW_A\" FriendlyName=\"MS\" FilePath=\"%WINDIR%\\\\*\" />"):
    xml = ("<SiPolicy xmlns=\"urn:schemas-microsoft-com:sipolicy\"><Rules>" + "".join(
        "<Rule><Option>" + o + "</Option></Rule>" for o in options) + "</Rules><FileRules>" + file_rules +
        "</FileRules></SiPolicy>")
    settings = [{"settingInstance": {"settingDefinitionId": "device_vendor_msft_policy_config_applicationcontrol_policies_{policyguid}_xml",
                                     "simpleSettingValue": {"value": xml}}}]
    return {"id": "x-" + name, "name": name, "templateReference": {"templateFamily": "endpointSecurityApplicationControl"},
            "settings": settings, "assignments": [ALL_DEVICES] if assignments is None else assignments}


def applocker(name, mode="Enabled", assignments=None, encrypted=False, allow_path="%WINDIR%\\*"):
    value = ("<RuleCollection Type=\"Script\" EnforcementMode=\"" + mode + "\"><FilePathRule Id=\"1\" Name=\"r\" "
             "UserOrGroupSid=\"S-1-1-0\" Action=\"Allow\"><Conditions><FilePathCondition Path=\"" + allow_path +
             "\" /></Conditions></FilePathRule></RuleCollection>")
    return {"@odata.type": "#microsoft.graph.windows10CustomConfiguration", "id": "c-" + name, "displayName": name,
            "omaSettings": [{"@odata.type": "#microsoft.graph.omaSettingString",
                             "omaUri": "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/Grp1/Script/Policy",
                             "isEncrypted": encrypted, "value": None if encrypted else value}],
            "assignments": [ALL_DEVICES] if assignments is None else assignments}


OTHER_POLICY = {"id": "o", "name": "BitLocker", "templateReference": {"templateFamily": "endpointSecurityDiskEncryption"},
                "settings": [{"settingInstance": {"settingDefinitionId": "device_vendor_msft_bitlocker_requiredeviceencryption",
                                                  "choiceSettingValue": {"value": "x_1"}}}],
                "assignments": [ALL_DEVICES]}


def graph(items):
    return {"@odata.context": "https://graph.microsoft.com/beta/$metadata#x", "value": items}


def body(policies, profiles=()):
    return {"appControlPolicies": graph(list(policies)), "deviceConfigurations": graph(list(profiles))}


PASSING = body([OTHER_POLICY, app_control("ACfB enforce"), app_control("Pilot audit", "audit", [group("g1")])])
FAILING = body([OTHER_POLICY, app_control("ACfB audit", "audit"), app_control("Servers", "enforce", [group("g-srv")])])


def stringify(v):
    if isinstance(v, dict):
        return {k: stringify(x) for k, x in v.items()}
    if isinstance(v, list):
        return [stringify(x) for x in v]
    return str(v)


def ts_wrap(b):
    return {"data": {"apiResponse": b}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
def test_pass_and_fail(form, loader):
    good, bad = PASSING, FAILING
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    got, out = value(good, loader)
    assert got is True
    assert "ACfB enforce (App Control, enforce, all devices or all users)" in out["additionalInfo"]["evaluation"]["passReasons"][0]
    got, out = value(bad, loader)
    assert got is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "ACfB audit (App Control, audit" in reason and "Servers (App Control, enforce, assigned to groups only)" in reason


def test_xml_policy_modes():
    assert value(body([xml_policy("x", ["Enabled:UMCI"])]))[0] is True
    assert value(body([xml_policy("x", ["Enabled:UMCI", "Enabled:Audit Mode"])]))[0] is False
    got, out = value(body([xml_policy("x", ["Enabled:Unsigned System Integrity Policy"])]))
    assert got is False and "kernel-only" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_applocker_script_rules():
    assert value(body([], [applocker("AL")]))[0] is True
    assert value(body([], [applocker("AL", "AuditOnly")]))[0] is False
    assert value(body([], [applocker("AL", assignments=[ALL_DEVICES, group("g", exclude=True)])]))[0] is False
    assert value(body([], [applocker("AL", encrypted=True)]))[0] is None


def test_nothing_configured_is_not_evaluated():
    got, out = value(body([OTHER_POLICY]))
    assert got is None
    assert "Group Policy" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_unreadable_mode_or_assignments_is_not_evaluated_unless_something_enforces():
    p = app_control("x")
    p["settings"] = [{"settingInstance": {"settingDefinitionId": BUILT_IN, "choiceSettingValue": {"value": "unknown"}}}]
    assert value(body([p]))[0] is None
    q = app_control("y")
    del q["assignments"]
    assert value(body([q]))[0] is None
    assert value(body([p, q, app_control("z")]))[0] is True


def test_partial_reads():
    b = body([app_control("x", "audit")])
    b["deviceConfigurations"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/next"
    assert value(b)[0] is None
    b = body([app_control("x", "audit")])
    b["paginationStats"] = {"appControlPolicies": {"paginationTruncated": True}}
    assert value(b)[0] is None
    b = body([app_control("x")])
    b["deviceConfigurations"] = {"error": {"code": "Forbidden", "message": "denied"}}
    assert value(b)[0] is True
    b = body([app_control("x", "audit")])
    del b["deviceConfigurations"]
    assert value(b)[0] is None


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"value": []},
    body([]),
]


@pytest.mark.parametrize("b", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(b):
    for wrapped in (b, ts_wrap(b)):
        got, out = value(wrapped)
        assert got is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def test_except_path_is_not_evaluated():
    got, out = value(Poisoned())
    assert got is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_key_is_new_and_no_existing_transform_emits_it():
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not fn.endswith(".py") or fn.startswith("test_") or path == FILE:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                if '"' + KEY + '"' in fh.read():
                    seen.append(path)
    assert seen == []


def test_script_enforcement_disabled_is_not_constrained_language():
    got, out = value(body([xml_policy("x", ["Enabled:UMCI", "Disabled:Script Enforcement"])]))
    assert got is False
    assert "script enforcement disabled" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("path", ["*", "*.ps1", "*\\Temp\\*", "%OSDRIVE%\\*", "%TEMP%\\*", "%USERPROFILE%\\Downloads\\*",
                                  "C:\\Users\\*", "D:\\Users\\*", "%OSDRIVE%\\ProgramData\\*"])
def test_applocker_allowing_user_writable_paths_is_not_enforcing(path):
    got, out = value(body([], [applocker("AL", allow_path=path)]))
    assert got is False
    assert "allows user-writable paths" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_applocker_allowing_program_files_still_enforces():
    assert value(body([], [applocker("AL", allow_path="%PROGRAMFILES%\\*")]))[0] is True


def test_filter_id_without_a_type_is_filtered():
    t = {"target": {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget",
                    "deviceAndAppManagementAssignmentFilterId": "11111111-1111-1111-1111-111111111111"}}
    got, out = value(body([app_control("x", assignments=[t])]))
    assert got is False
    assert "uses an assignment filter" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def collection(rules):
    xml = "<RuleCollection Type=\"Script\" EnforcementMode=\"Enabled\">" + "".join(
        "<FilePathRule Id=\"" + str(i) + "\" Name=\"r\" UserOrGroupSid=\"" + sid + "\" Action=\"Allow\"><Conditions>"
        "<FilePathCondition Path=\"" + path + "\" /></Conditions>" + extra + "</FilePathRule>"
        for i, (sid, path, extra) in enumerate(rules)) + "</RuleCollection>"
    p = applocker("AL")
    p["omaSettings"][0]["value"] = xml
    return p


def test_applocker_default_rules_are_enforcing():
    rules = [("S-1-1-0", "%WINDIR%\\*", ""), ("S-1-1-0", "%PROGRAMFILES%\\*", ""), ("S-1-5-32-544", "*", "")]
    assert value(body([], [collection(rules)]))[0] is True


@pytest.mark.parametrize("sid", ["S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-21-1111111111-2222222222-3333333333-513"])
def test_a_broad_principal_allowing_everything_is_not_enforcing(sid):
    assert value(body([], [collection([(sid, "*", "")])]))[0] is False


def test_a_broad_rule_with_exceptions_is_not_read():
    rules = [("S-1-1-0", "*", "<Exceptions><FilePathException Path=\"%TEMP%\\*\" /></Exceptions>")]
    assert value(body([], [collection(rules)]))[0] is None


def test_unknown_principals_and_paths_are_not_read():
    # an Entra group SID allowing everything cannot be shown narrow
    assert value(body([], [collection([("S-1-12-1-1111111111-2222222222-3333333333-4444444444", "*", "")])]))[0] is None
    # an unlisted path for Everyone cannot be shown safe
    assert value(body([], [collection([("S-1-1-0", "%OSDRIVE%\\Tools\\*", "")])]))[0] is None
    # a later broad rule still fails after an unreadable one
    rules = [("S-1-1-0", "*", "<Exceptions><FilePathException Path=\"x\" /></Exceptions>"), ("S-1-1-0", "C:\\Users\\*", "")]
    assert value(body([], [collection(rules)]))[0] is False


def test_an_enforced_collection_with_no_rules_is_not_enforcing():
    p = applocker("AL")
    p["omaSettings"][0]["value"] = "<RuleCollection Type=\"Script\" EnforcementMode=\"Enabled\" />"
    got, out = value(body([], [p]))
    assert got is False
    assert "no script rules" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    q = applocker("AL")
    q["omaSettings"][0]["value"] = ("<RuleCollection Type=\"Script\" EnforcementMode=\"Enabled\"><FileHashRule Id=\"1\" "
                                    "Name=\"h\" UserOrGroupSid=\"S-1-1-0\" Action=\"Allow\" /></RuleCollection>")
    assert value(body([], [q]))[0] is True


def test_a_safe_root_with_dot_dot_is_not_read():
    assert value(body([], [collection([("S-1-1-0", "%WINDIR%\\..\\Users\\*", "")])]))[0] is not True


@pytest.mark.parametrize("rule", ["<Allow ID=\"ID_ALLOW_A_1\" FriendlyName=\"Allow All\" FileName=\"*\" />",
                                  "<Allow ID=\"ID_ALLOW_A_2\" FriendlyName=\"Allow All\" FilePath=\"*\" />",
                                  "<Allow ID=\"ID_ALLOW_A_3\" FriendlyName=\"Temp\" FilePath=\"%TEMP%\\\\*\" />"])
def test_allow_all_or_user_writable_wdac_is_not_enforcing(rule):
    got, out = value(body([xml_policy("AllowAll", ["Enabled:UMCI"], file_rules=rule)]))
    assert got is False
    assert "allows all files" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_options_are_read_only_inside_option_elements():
    p = xml_policy("x", [])
    s = p["settings"][0]["settingInstance"]["simpleSettingValue"]
    s["value"] = s["value"].replace("<Rules>", "<!-- <Option>Enabled:UMCI</Option> --><Rules>")
    assert value(body([p]))[0] is False


def test_applocker_profiles_merge_on_devices():
    broad = collection([("S-1-1-0", "*", "")])
    broad["assignments"] = [group("g-sales")]
    got, out = value(body([], [applocker("Baseline AL"), broad]))
    assert got is False
    assert "merged with a broad rule" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    unreadable = applocker("Secret AL", encrypted=True, assignments=[group("g-x")])
    assert value(body([], [applocker("Baseline AL"), unreadable]))[0] is None
    # an unassigned broad profile reaches no device
    broad["assignments"] = []
    assert value(body([], [applocker("Baseline AL"), broad]))[0] is True
    # App Control enforcement is not undone by an AppLocker profile
    broad["assignments"] = [group("g-sales")]
    assert value(body([app_control("ACfB")], [broad]))[0] is True
