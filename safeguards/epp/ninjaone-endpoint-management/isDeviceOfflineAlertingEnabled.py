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


def condition_is_offline_alert(cond):
    if not isinstance(cond, dict):
        return False
    text_bits = []
    for key in ["type", "conditionType", "name", "category", "alertType"]:
        val = cond.get(key)
        if isinstance(val, str):
            text_bits.append(val.lower())
    combined = " ".join(text_bits)
    if "offline" in combined:
        return True
    return False


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
    policies_with_offline_condition = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        conditions = policy.get("conditions")
        if not isinstance(conditions, list):
            continue
        for cond in conditions:
            if condition_is_offline_alert(cond):
                policies_with_offline_condition.append(policy.get("name") or policy.get("id"))
                break

    is_enabled = len(policies_with_offline_condition) > 0

    input_summary = {
        "totalPolicies": total_policies,
        "policiesWithOfflineCondition": len(policies_with_offline_condition),
    }

    if is_enabled:
        sample = policies_with_offline_condition[:5]
        pass_reasons = [
            f"Found {len(policies_with_offline_condition)} of {total_policies} policies with an offline-duration alert condition configured, including: {sample}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Scanned {total_policies} policies via getPolicies; none of the returned 'conditions' arrays contain an offline-duration alert condition (no condition entries reference 'offline' in type/name/category fields)."
        ]
        recommendations = [
            "Configure a device offline condition (e.g. an 'Offline' condition with a duration threshold) on at least one active policy so technicians are alerted when devices go offline beyond the configured duration."
        ]

    result = {
        "isDeviceOfflineAlertingEnabled": is_enabled,
        "totalPolicies": total_policies,
        "policiesWithOfflineCondition": len(policies_with_offline_condition),
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
            "transformationId": "isDeviceOfflineAlertingEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
