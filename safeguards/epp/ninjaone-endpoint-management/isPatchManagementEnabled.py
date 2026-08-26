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

    is_patch_management_enabled = len(enabled_names) > 0

    total_os_policies = len(os_policies)
    input_summary = {
        "totalPolicies": len(policies),
        "totalOsPolicies": total_os_policies,
        "policiesWithPatchEnabled": len(enabled_names),
        "policiesWithPatchDisabled": len(disabled_names),
        "policiesWithNoEvidence": len(no_evidence_names),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_patch_management_enabled:
        pass_reasons.append(
            f"{len(enabled_names)} of {total_os_policies} OS-targeting policies report an active patch "
            f"management configuration: {', '.join(enabled_names[:5])}."
        )
    else:
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
