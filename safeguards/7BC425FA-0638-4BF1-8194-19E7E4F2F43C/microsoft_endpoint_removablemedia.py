"""Transformation: isRemovableMediaControlled (Windows Defender One-Click, Intune removable-storage policies).

Vendor: Microsoft Defender for Endpoint / Microsoft Intune  |  Category: Endpoint Security

Input: getRemovableStoragePolicies, one Microsoft Graph JSON batch (POST https://graph.microsoft.com/beta/$batch,
application permission DeviceManagementConfiguration.Read.All on Microsoft Graph) carrying two reads:
  id "deviceConfigurations"  GET /deviceManagement/deviceConfigurations?$expand=assignments
  id "configurationPolicies" GET /deviceManagement/configurationPolicies?$expand=settings,assignments
A plain Graph list body ({"value": [...]}) from either read, or a bare list, is also accepted.

A policy restricts removable storage when it sets any of:
  deviceConfigurations (windows10GeneralConfiguration)  storageBlockRemovableStorage == true
  deviceConfigurations (windows10CustomConfiguration) OMA-URI
      ./Device/Vendor/MSFT/Policy/Config/Storage/RemovableDiskDenyWriteAccess          = 1
      ./Device/Vendor/MSFT/Policy/Config/ADMX_RemovableStorage/<...Deny...>             = <enabled/>
      ./Vendor/MSFT/Defender/Configuration/DefaultEnforcement                           = 2 (Deny)
      ./Vendor/MSFT/Defender/Configuration/DeviceControl/PolicyRules/...                rule XML with <Type>Deny</Type>
  configurationPolicies (settings catalog / Endpoint security "Device control")
      device_vendor_msft_policy_config_storage_removablediskdenywriteaccess            value ..._1
      device_vendor_msft_policy_config_admx_removablestorage_*deny*                    value ..._1 (Enabled)
      device_vendor_msft_defender_configuration_defaultenforcement                     value ..._2 (Deny)
      device_vendor_msft_defender_configuration_devicecontrol_* entry type             value ..._deny
A Defender device-control rule whose entries are only AuditAllowed/AuditDenied is AUDIT-ONLY: it is reported
(auditOnlyPolicies) but does not pass, the same line Sophos draws for "monitor but do not block"
(safeguards/epp/sophos/isremovablemediacontrolled.py).

Verdict: true when at least one restricting policy is assigned to an include target (any assignment that is
not an exclusion group). Disabled or unassigned restricting policies govern no device and do not pass.
What this proves: Intune pushes a removable-storage block (or write-deny) policy to some devices or users.
What it does not prove: that every device is in scope (coversAllDevices reports allDevices/allLicensedUsers
targets), GPO-only configuration, or devices Intune does not manage.

Fails closed: an error body, a batch sub-response that is not 200, an @odata.nextLink (partial read), no
recognisable policy list, or a restricting policy whose assignments were not returned (the $expand did not
run) return isRemovableMediaControlled None with a dataCollection error. A complete read with no restricting
assigned policy returns false.
"""
import json
from datetime import datetime

KEY = "isRemovableMediaControlled"
AUDIT_ONLY_PASSES = False
MAX_SETTING_NODES = 20000
EXCLUSION_TARGET = "#microsoft.graph.exclusiongroupassignmenttarget"
ALL_TARGETS = ["#microsoft.graph.alldevicesassignmenttarget", "#microsoft.graph.alllicensedusersassignmenttarget"]
OMA_DENY_WRITE = "/policy/config/storage/removablediskdenywriteaccess"
OMA_ADMX = "/policy/config/admx_removablestorage/"
OMA_DEFAULT_ENFORCEMENT = "/defender/configuration/defaultenforcement"
OMA_DEVICE_CONTROL = "/defender/configuration/devicecontrol/policyrules"
DEF_DENY_WRITE = "device_vendor_msft_policy_config_storage_removablediskdenywriteaccess"
DEF_ADMX_PREFIX = "device_vendor_msft_policy_config_admx_removablestorage_"
DEF_DEFAULT_ENFORCEMENT = "device_vendor_msft_defender_configuration_defaultenforcement"
DEF_DEVICE_CONTROL = "device_vendor_msft_defender_configuration_devicecontrol"


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, bytes):
        try:
            input_data = input_data.decode("utf-8")
        except Exception:
            input_data = ""
    if isinstance(input_data, str):
        try:
            input_data = json.loads(input_data)
        except Exception:
            input_data = None
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success", "errors": transform_err_list,
                               "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": "microsoft_endpoint_removablemedia",
                         "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"},
        },
    }


def unevaluated(problem, validation):
    return create_response({KEY: None}, validation, fail_reasons=[problem], api_errors=[problem],
                           recommendations=["Confirm the One-Click app holds DeviceManagementConfiguration.Read.All "
                                            "(Microsoft Graph) with admin consent."])


def is_partial(body):
    link = body.get("@odata.nextLink")
    return isinstance(link, str) and bool(link.strip())


def collect_policies(data):
    """Return (policies, None) from a complete read, or (None, problem)."""
    if isinstance(data, list):
        return data, None
    if not isinstance(data, dict):
        return None, "No Microsoft Graph response envelope; nothing to evaluate."
    if data.get("error") or data.get("errors"):
        err = data.get("error") or data.get("errors")
        return None, "Microsoft Graph returned an error: " + json.dumps(err)[:300]
    responses = data.get("responses")
    if isinstance(responses, list):
        if not responses:
            return None, "The Graph batch returned no sub-responses."
        policies = []
        for sub in responses:
            if not isinstance(sub, dict):
                return None, "A Graph batch sub-response is not an object."
            status = sub.get("status")
            body = sub.get("body")
            label = str(sub.get("id") or "?")
            if status != 200:
                detail = ""
                if isinstance(body, dict) and isinstance(body.get("error"), dict):
                    detail = ": " + str(body["error"].get("code") or "")[:80]
                return None, "Graph batch read '" + label + "' returned status " + str(status) + detail + "."
            if not isinstance(body, dict) or not isinstance(body.get("value"), list):
                return None, "Graph batch read '" + label + "' has no value list."
            if is_partial(body):
                return None, "Graph batch read '" + label + "' has more pages (@odata.nextLink); a partial read is not scored."
            policies.extend(body["value"])
        return policies, None
    if isinstance(data.get("value"), list):
        if is_partial(data):
            return None, "The Graph policy list has more pages (@odata.nextLink); a partial read is not scored."
        return data["value"], None
    return None, "The response is not a Graph policy list or batch."


def lower_text(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value).strip().lower()
    return ""


def classify_device_control_xml(text):
    compact = text.replace(" ", "")
    if "<type>deny</type>" in compact:
        return "block"
    if "<type>auditdenied</type>" in compact or "<type>auditallowed</type>" in compact:
        return "audit"
    return None


def stronger(current, found):
    if current == "block" or found == "block":
        return "block"
    if current == "audit" or found == "audit":
        return "audit"
    return None


def classify_oma(oma_settings):
    level = None
    if not isinstance(oma_settings, list):
        return level
    for item in oma_settings:
        if not isinstance(item, dict):
            continue
        uri = lower_text(item.get("omaUri"))
        value = lower_text(item.get("value"))
        if not uri:
            continue
        if uri.endswith(OMA_DENY_WRITE) and value == "1":
            level = stronger(level, "block")
        elif OMA_ADMX in uri and "deny" in uri and "<enabled" in value:
            level = stronger(level, "block")
        elif uri.endswith(OMA_DEFAULT_ENFORCEMENT) and value == "2":
            level = stronger(level, "block")
        elif OMA_DEVICE_CONTROL in uri and value:
            level = stronger(level, classify_device_control_xml(value))
    return level


def setting_pairs(settings):
    """Flatten settings-catalog instances (with children) into (definitionId, value) pairs."""
    pairs = []
    stack = []
    if isinstance(settings, list):
        for s in settings:
            if isinstance(s, dict):
                stack.append(s.get("settingInstance", s))
    guard = 0
    while stack:
        guard = guard + 1
        if guard > MAX_SETTING_NODES:
            raise ValueError("settings tree exceeds " + str(MAX_SETTING_NODES) + " nodes; not judged")
        inst = stack.pop()
        if not isinstance(inst, dict):
            continue
        def_id = lower_text(inst.get("settingDefinitionId"))
        choice = inst.get("choiceSettingValue")
        if isinstance(choice, dict):
            pairs.append((def_id, lower_text(choice.get("value"))))
            for child in choice.get("children") or []:
                stack.append(child)
        simple = inst.get("simpleSettingValue")
        if isinstance(simple, dict):
            pairs.append((def_id, lower_text(simple.get("value"))))
        for coll_key in ["groupSettingCollectionValue", "choiceSettingCollectionValue", "simpleSettingCollectionValue"]:
            coll = inst.get(coll_key)
            if isinstance(coll, list):
                for entry in coll:
                    if not isinstance(entry, dict):
                        continue
                    if "value" in entry and "children" not in entry:
                        pairs.append((def_id, lower_text(entry.get("value"))))
                    for child in entry.get("children") or []:
                        stack.append(child)
        group = inst.get("groupSettingValue")
        if isinstance(group, dict):
            for child in group.get("children") or []:
                stack.append(child)
    return pairs


def classify_settings(settings):
    level = None
    for pair in setting_pairs(settings):
        def_id = pair[0]
        value = pair[1]
        if def_id == DEF_DENY_WRITE and value.endswith("_1"):
            level = stronger(level, "block")
        elif def_id.startswith(DEF_ADMX_PREFIX) and "deny" in def_id and value.endswith("_1"):
            level = stronger(level, "block")
        elif def_id == DEF_DEFAULT_ENFORCEMENT and value.endswith("_2"):
            level = stronger(level, "block")
        elif def_id.startswith(DEF_DEVICE_CONTROL):
            if value.endswith("_deny"):
                level = stronger(level, "block")
            elif value.endswith("_auditdenied") or value.endswith("_auditallowed"):
                level = stronger(level, "audit")
            elif "<type>" in value:
                level = stronger(level, classify_device_control_xml(value))
    return level


def classify_policy(policy):
    level = None
    if policy.get("storageBlockRemovableStorage") is True:
        level = "block"
    level = stronger(level, classify_oma(policy.get("omaSettings")))
    level = stronger(level, classify_settings(policy.get("settings")))
    return level


def assignment_state(policy):
    """Return (state, coversAll): state is 'assigned', 'unassigned' or 'unknown'."""
    assignments = policy.get("assignments")
    if not isinstance(assignments, list):
        if policy.get("isAssigned") is True:
            return "assigned", False
        if policy.get("isAssigned") is False:
            return "unassigned", False
        return "unknown", False
    included = False
    covers_all = False
    for a in assignments:
        if not isinstance(a, dict):
            continue
        target = a.get("target")
        odata = lower_text(target.get("@odata.type")) if isinstance(target, dict) else ""
        if odata == EXCLUSION_TARGET:
            continue
        included = True
        if odata in ALL_TARGETS:
            covers_all = True
    return ("assigned" if included else "unassigned"), covers_all


def policy_name(policy):
    return str(policy.get("displayName") or policy.get("name") or policy.get("id") or "unnamed")[:120]


def transform(input):
    try:
        data, validation = extract_input(input)
        policies, problem = collect_policies(data)
        if problem:
            return unevaluated(problem, validation)
        passing = []
        audit_only = []
        unassigned = []
        unknown = []
        covers_all = False
        for policy in policies:
            if not isinstance(policy, dict):
                return unevaluated("A Graph policy record is not an object.", validation)
            level = classify_policy(policy)
            if level is None:
                continue
            state, all_targets = assignment_state(policy)
            name = policy_name(policy)
            if state == "unknown":
                unknown.append(name)
            elif state == "unassigned":
                unassigned.append(name)
            elif level == "block" or AUDIT_ONLY_PASSES:
                passing.append(name)
                if all_targets:
                    covers_all = True
            else:
                audit_only.append(name)
        summary = {
            "policiesRead": len(policies),
            "restrictingAssignedPolicies": passing[:20],
            "auditOnlyPolicies": audit_only[:20],
            "restrictingUnassignedPolicies": unassigned[:20],
            "restrictingPoliciesWithoutAssignments": unknown[:20],
            "coversAllDevices": covers_all,
        }
        if passing:
            result = {KEY: True, "coversAllDevices": covers_all, "restrictingPolicyCount": len(passing)}
            reason = ("Intune policy blocks removable storage and is assigned: " + ", ".join(passing[:5])
                      + (" (targets all devices or all licensed users)" if covers_all else " (group-targeted)"))
            return create_response(result, validation, pass_reasons=[reason], input_summary=summary)
        if unknown:
            return unevaluated("Removable-storage policies were found but their assignments were not returned ("
                               + ", ".join(unknown[:5]) + "); assignment cannot be shown.", validation)
        fails = ["No assigned Intune policy blocks removable storage (" + str(len(policies)) + " policies read)."]
        if audit_only:
            fails.append("Audit-only device control does not block: " + ", ".join(audit_only[:5]) + ".")
        if unassigned:
            fails.append("Restricting policies assigned to no one: " + ", ".join(unassigned[:5]) + ".")
        result = {KEY: False, "coversAllDevices": False, "restrictingPolicyCount": 0}
        return create_response(result, validation, fail_reasons=fails, input_summary=summary,
                               recommendations=["Assign an Intune device control or device restriction policy that "
                                                "denies (or makes read-only) removable storage."])
    except Exception as e:
        return create_response({KEY: None}, {"status": "error", "errors": [], "warnings": []},
                               fail_reasons=["Transformation error: " + str(e)], transformation_errors=[str(e)])
