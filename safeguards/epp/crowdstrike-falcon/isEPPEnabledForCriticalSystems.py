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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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


CRITICAL_KEYWORDS = [
    "critical", "server", "domain controller", "domain-controller",
    "dc", "tier0", "tier 0", "tier-0",
]


def is_critical_group_name(name):
    if not name:
        return False
    lower_name = name.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in lower_name:
            return True
    return False


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error"):
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"CrowdStrike API returned an error: {err_msg}")

    policies = data.get("resources") or []
    if not isinstance(policies, list):
        policies = []

    critical_group_names = set()
    covered_critical_group_names = set()
    inspected_policies = []

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_enabled = bool(policy.get("enabled"))
        policy_name = policy.get("name") or policy.get("id") or "unnamed-policy"
        groups = policy.get("groups") or []
        if not isinstance(groups, list):
            groups = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            group_name = group.get("name") or group.get("id") or ""
            if is_critical_group_name(group_name):
                critical_group_names.add(group_name)
                if policy_enabled:
                    covered_critical_group_names.add(group_name)
                    inspected_policies.append(f"{policy_name} (enabled) -> {group_name}")

    total_critical = len(critical_group_names)
    total_covered = len(covered_critical_group_names)

    if total_critical > 0:
        is_enabled_for_critical = total_covered == total_critical
    else:
        is_enabled_for_critical = False

    input_summary = {
        "totalPolicies": len(policies),
        "criticalHostGroupsFound": total_critical,
        "criticalHostGroupsCovered": total_covered,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            "The getCombinedPreventionPolicies API call returned an error; no prevention policy data was available to evaluate critical system coverage."
        )
        recommendations.append(
            "Verify CrowdStrike API credentials and connectivity, then re-run the scan to retrieve prevention policy assignments."
        )
    elif total_critical == 0:
        fail_reasons.append(
            "No host groups matching critical-system naming patterns (e.g. 'server', 'domain controller', 'tier0', 'critical') were found across the "
            f"{len(policies)} prevention policies retrieved, so critical-system EPP coverage could not be confirmed."
        )
        recommendations.append(
            "Tag critical host groups (servers, domain controllers, tier-0 systems) with identifiable names and assign an enabled Prevention Policy to them."
        )
    elif is_enabled_for_critical:
        pass_reasons.append(
            f"All {total_critical} critical-tagged host group(s) ({', '.join(sorted(covered_critical_group_names))}) are assigned to a Prevention Policy with enabled=true."
        )
        if inspected_policies:
            pass_reasons.append(
                "Cross-referenced policy-to-group assignments: " + "; ".join(inspected_policies[:5])
            )
    else:
        uncovered = sorted(critical_group_names - covered_critical_group_names)
        fail_reasons.append(
            f"{total_critical - total_covered} of {total_critical} critical host group(s) ({', '.join(uncovered)}) are not covered by any Prevention Policy with enabled=true."
        )
        recommendations.append(
            f"Assign an enabled Prevention Policy to the following critical host groups: {', '.join(uncovered)}."
        )

    result = {
        "isEPPEnabledForCriticalSystems": is_enabled_for_critical,
        "criticalHostGroupsFound": total_critical,
        "criticalHostGroupsCovered": total_covered,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPEnabledForCriticalSystems",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
        api_errors=api_errors,
    )
