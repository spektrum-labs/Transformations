import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


OS_NODE_CLASSES = set([
    "WINDOWS_SERVER", "WINDOWS_WORKSTATION", "MAC", "MAC_SERVER",
    "LINUX_WORKSTATION", "LINUX_SERVER",
])


def devices_in_scope(data):
    """The device list the workflow put beside the organizations/policies, or None when there is none.

    With the definition's optional organizationFilter set, getDevicesDetailed returns only the devices
    of the organizations in scope, so this list is what decides which organizations and policies count.
    Without it (older workflow, or a bare list) the check judges everything it was given, as before.
    """
    if isinstance(data, dict) and isinstance(data.get("devices"), list):
        return [d for d in data["devices"] if isinstance(d, dict)]
    return None


def policies_for_devices(policies, devices):
    """Only the policies that apply to the given devices: each device's policyId and rolePolicyId, plus
    every ancestor through parentPolicyId (a child policy inherits its parent's settings)."""
    by_id = {}
    for p in policies:
        if isinstance(p, dict):
            by_id[p.get("id")] = p
    wanted = set()
    for d in devices:
        for field in ("policyId", "rolePolicyId"):
            value = d.get(field)
            if isinstance(value, int) and not isinstance(value, bool):
                wanted.add(value)
    pending = list(wanted)
    while pending:
        parent = (by_id.get(pending.pop()) or {}).get("parentPolicyId")
        if isinstance(parent, int) and not isinstance(parent, bool) and parent not in wanted:
            wanted.add(parent)
            pending.append(parent)
    return [p for p in policies if isinstance(p, dict) and p.get("id") in wanted]


def policy_patch_enabled(policy):
    """Inspect a single policy record for evidence patch management is enabled.

    Checks (in priority order):
      1. An explicit nested patch-management settings object with an
         'enabled' flag or a non-disabled 'mode'/'status' string.
      2. A 'conditions' entry whose type/conditionType mentions PATCH.
      3. The policy-level 'enabled' flag as a last-resort signal that the
         policy itself (and whatever patching behavior it carries) is on.

    Returns a tuple (has_evidence: bool, enabled: bool, source: str).
    """
    for key in ("patchManagement", "osPatchManagement", "patchManagementSettings"):
        val = policy.get(key)
        if isinstance(val, dict) and val:
            mode = val.get("mode") or val.get("status") or ""
            enabled_flag = val.get("enabled")
            if enabled_flag is True:
                return True, True, key
            if enabled_flag is False:
                return True, False, key
            if isinstance(mode, str) and mode != "":
                is_on = mode.upper() not in ("DISABLED", "OFF", "NONE")
                return True, is_on, key

    conditions = policy.get("conditions")
    if isinstance(conditions, list) and conditions:
        for c in conditions:
            if isinstance(c, dict):
                ctype = str(c.get("conditionType") or c.get("type") or "").upper()
                if "PATCH" in ctype:
                    return True, True, "conditions"

    enabled_val = policy.get("enabled")
    if isinstance(enabled_val, bool):
        return True, enabled_val, "enabled"

    return False, False, "none"


# NinjaOne's /v2/policies list returns a policy summary only (id, name, nodeClass, parentPolicyId,
# description): the OS patching toggle is not in the public API, so policy records alone can never show
# patching is on. The workflow also hands over /v2/queries/os-patch-installs as "osPatchInstalls"; an
# INSTALLED record on an in-scope OS device within this window is direct evidence that patching runs.
INSTALL_WINDOW_DAYS = 30


def recent_installs(data, devices):
    """(count, problem): INSTALLED patch records in the window on in-scope OS devices, or why none can be read.

    No "osPatchInstalls" part (older workflow) or an unreadable one returns (0, problem) and never a pass."""
    part = data.get("osPatchInstalls") if isinstance(data, dict) else None
    if part is None:
        return 0, None
    records = part.get("results") if isinstance(part, dict) else part
    if not isinstance(records, list):
        return 0, "the patch install read carries no record list"
    os_device_ids = None
    if devices is not None:
        os_device_ids = set(d.get("id") for d in devices if d.get("nodeClass") in OS_NODE_CLASSES)
    cutoff = datetime.utcnow().timestamp() - INSTALL_WINDOW_DAYS * 86400
    count = 0
    for rec in records:
        if not isinstance(rec, dict) or rec.get("status") != "INSTALLED":
            continue
        if os_device_ids is not None and rec.get("deviceId") not in os_device_ids:
            continue
        at = rec.get("installedAt")
        if isinstance(at, (int, float)) and not isinstance(at, bool) and at >= cutoff:
            count += 1
    return count, None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else []

    if isinstance(data, list):
        policies = data
    elif isinstance(data, dict):
        policies = data.get("data") or data.get("results") or data.get("policies") or []
        if not isinstance(policies, list):
            policies = []
    else:
        policies = []

    devices = devices_in_scope(data)
    policies_out_of_scope = 0
    if devices is not None:
        scoped = policies_for_devices(policies, devices)
        policies_out_of_scope = len(policies) - len(scoped)
        policies = scoped

    os_policies = [p for p in policies if isinstance(p, dict) and (p.get("nodeClass") in OS_NODE_CLASSES)]

    enabled_names = []
    disabled_names = []
    no_evidence_names = []

    for p in os_policies:
        has_evidence, is_enabled, source = policy_patch_enabled(p)
        label = p.get("name") or str(p.get("id"))
        if not has_evidence:
            no_evidence_names.append(label)
        elif is_enabled:
            enabled_names.append(f"{label} ({source})")
        else:
            disabled_names.append(f"{label} ({source})")

    installs, installs_problem = recent_installs(data, devices)
    is_patch_management_enabled = len(enabled_names) > 0 or installs > 0

    total_os_policies = len(os_policies)
    input_summary = {
        "totalPolicies": len(policies),
        "totalOsPolicies": total_os_policies,
        "policiesWithPatchEnabled": len(enabled_names),
        "policiesWithPatchDisabled": len(disabled_names),
        "policiesWithNoEvidence": len(no_evidence_names),
        "recentPatchInstalls": installs,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if enabled_names:
        pass_reasons.append(
            f"{len(enabled_names)} of {total_os_policies} OS-targeting policies report an active patch "
            f"management configuration: {', '.join(enabled_names[:5])}."
        )
    if installs > 0:
        pass_reasons.append(
            f"NinjaOne installed {installs} OS patch(es) on in-scope Windows/Mac/Linux devices in the last "
            f"{INSTALL_WINDOW_DAYS} days, so OS patch management is running."
        )
    if not is_patch_management_enabled:
        if installs_problem:
            fail_reasons.append(f"Patch install history could not be read: {installs_problem}.")
        if total_os_policies == 0:
            fail_reasons.append(
                "No OS-targeting policies (Windows/Mac/Linux server or workstation nodeClass) were returned "
                "by /v2/policies, so patch management configuration could not be confirmed."
            )
        elif no_evidence_names:
            fail_reasons.append(
                f"{len(no_evidence_names)} of {total_os_policies} OS policies expose no patch management "
                f"settings, conditions, or enabled flag in the policy record (e.g. {', '.join(no_evidence_names[:5])})."
            )
        elif disabled_names:
            fail_reasons.append(
                f"All {total_os_policies} OS policies with patch management evidence report it disabled: "
                f"{', '.join(disabled_names[:5])}."
            )
        else:
            fail_reasons.append(
                "No evidence of an enabled patch management configuration was found across OS-targeting policies."
            )
        recommendations.append(
            "Enable OS patch management on the Windows/Mac/Linux policies governing managed devices in NinjaOne."
        )

    result = {
        "isPatchManagementEnabled": is_patch_management_enabled,
        "totalOsPolicies": total_os_policies,
        "policiesWithPatchEnabled": len(enabled_names),
        "policiesOutOfScope": policies_out_of_scope,
        "recentPatchInstalls": installs,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
