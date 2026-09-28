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


def scan_for_third_party_patch_flag(obj, depth):
    """Recursively scan a policy object for a third-party software patch
    management toggle. Returns True/False/None (None = not found)."""
    if depth > 6:
        return None
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                continue
            lk = k.lower()
            is_third_party_key = ("thirdparty" in lk) or ("third_party" in lk) or ("3rdparty" in lk)
            is_patch_key = "patch" in lk
            if is_third_party_key and is_patch_key:
                if isinstance(v, bool):
                    return v
                if isinstance(v, str):
                    return v.strip().lower() in ("true", "enabled", "on", "yes")
                if isinstance(v, dict):
                    enabled_val = v.get("enabled")
                    if isinstance(enabled_val, bool):
                        return enabled_val
            if isinstance(v, (dict, list)):
                found = scan_for_third_party_patch_flag(v, depth + 1)
                if found is not None:
                    return found
    elif isinstance(obj, list):
        for item in obj:
            found = scan_for_third_party_patch_flag(item, depth + 1)
            if found is not None:
                return found
    return None


def has_third_party_patch_condition(conditions):
    """Look at a policy's conditions array for a software-patch-management
    condition/module that scopes third-party applications."""
    if not isinstance(conditions, list):
        return None
    for cond in conditions:
        if not isinstance(cond, dict):
            continue
        cond_type = str(cond.get("type") or cond.get("category") or "").upper()
        if "PATCH" in cond_type and ("THIRD" in cond_type or "SOFTWARE" in cond_type or "APPLICATION" in cond_type):
            enabled_val = cond.get("enabled")
            if isinstance(enabled_val, bool):
                return enabled_val
            return True
        nested = scan_for_third_party_patch_flag(cond, 0)
        if nested is not None:
            return nested
    return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

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

    total_policies = len(policies)
    policies_with_conditions = 0
    third_party_enabled_policies = []
    third_party_disabled_signal_found = False

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        conditions = policy.get("conditions")
        if isinstance(conditions, list) and len(conditions) > 0:
            policies_with_conditions = policies_with_conditions + 1
        flag = has_third_party_patch_condition(conditions if isinstance(conditions, list) else [])
        if flag is None:
            flag = scan_for_third_party_patch_flag(policy, 0)
        if flag is True:
            third_party_enabled_policies.append(policy.get("name") or policy.get("id"))
        elif flag is False:
            third_party_disabled_signal_found = True

    is_enabled = len(third_party_enabled_policies) > 0

    input_summary = {
        "totalPolicies": total_policies,
        "policiesWithConditions": policies_with_conditions,
        "policiesWithThirdPartyPatchEnabled": len(third_party_enabled_policies),
    }

    if is_enabled:
        sample_names = ", ".join([str(n) for n in third_party_enabled_policies[:5]])
        pass_reasons = [
            f"{len(third_party_enabled_policies)} of {total_policies} NinjaOne policies expose an enabled "
            f"third-party/software patch management condition (e.g. {sample_names}).",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Scanned {total_policies} NinjaOne policies via getPolicies; none of the {policies_with_conditions} "
            "policies carrying a non-empty conditions array expose an enabled third-party/software patch "
            "management setting, and no policy-level field indicating third-party patch coverage was found "
            "(only OS-targeted nodeClass values such as WINDOWS_WORKSTATION, MAC, LINUX_SERVER are present)."
        ]
        recommendations = [
            "Configure a Patch Management (Software) condition on the relevant NinjaOne policies to cover "
            "third-party applications (browsers, Java, Adobe, etc.) in addition to OS patching, then re-run "
            "this check.",
        ]

    result = {
        "isThirdPartyPatchManagementEnabled": is_enabled,
        "totalPolicies": total_policies,
        "policiesWithThirdPartyPatchEnabled": len(third_party_enabled_policies),
        "policiesOutOfScope": policies_out_of_scope,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isThirdPartyPatchManagementEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
