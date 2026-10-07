import json
import re
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
    "tier0", "tier 0", "tier-0",
]
# "dc" only as a whole word: as a substring it matched unrelated names.
CRITICAL_WORDS = ["dc"]


def is_critical_group_name(name):
    if not name:
        return False
    lower_name = str(name).lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in lower_name:
            return True
    for word in re.findall(r"[a-z0-9]+", lower_name):
        if word in CRITICAL_WORDS:
            return True
    return False


def is_true(value):
    """Stored CrowdStrike bodies carry booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def transform(input):
    """
    isEPPEnabledForCriticalSystems (CrowdStrike Falcon prevention policies,
    GET /policy/combined/prevention/v1).

    Rule: every prevention policy assigned to a critical host group (name matches CRITICAL_KEYWORDS,
    or the word "dc") must be enabled, for every platform. Falcon Complete assigns one policy per
    platform to the same group (MeasuredWin, MeasuredLin, MeasuredMac -> "Servers"); a disabled
    Windows policy on "Servers" is not masked by the enabled Linux one. The previous version counted
    a group as covered when ANY assigned policy was enabled, and read enabled with bool(), so the
    stored string "False" counted as enabled.

    Fails (false) when no critical host group is found. Not measured (dataCollection error, shown
    Unevaluated) on an API error, a body that is not a policy list, or a truncated list
    (meta.pagination.total larger than the policies returned).

    Does not prove: that the prevention toggles inside an enabled policy are switched on, or that
    every critical host is a member of a critical-named group.
    """
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            input = json.loads(input) if input.strip() else None
        except ValueError:
            input = None
    data, validation = extract_input(input)

    api_errors = []
    if data is None:
        api_errors.append("No response body from the prevention policies call")
    elif not isinstance(data, dict):
        api_errors.append("Prevention policies response is not an object")
    else:
        if data.get("error") or str(data.get("status", "")).lower() == "error":
            err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
            api_errors.append(f"CrowdStrike API returned an error: {err_msg}")
        vendor_errors = data.get("errors")
        if isinstance(vendor_errors, list) and vendor_errors and not data.get("resources"):
            api_errors.append("CrowdStrike API returned errors: " + json.dumps(vendor_errors)[:300])
        if not api_errors and not isinstance(data.get("resources"), list):
            api_errors.append("Prevention policies response has no resources list")

    policies = []
    if not api_errors:
        policies = [p for p in data.get("resources") if isinstance(p, dict)]
        meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
        pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
        total = as_int(pagination.get("total"))
        if (total is not None and total > len(policies)) or is_true(pagination.get("truncated")):
            api_errors.append(
                f"Prevention policy list was truncated ({len(policies)} of {total} returned); an unread policy "
                "could be a disabled one on a critical host group"
            )
            policies = []

    # group name -> {platform -> [(policy name, enabled)]}
    critical = {}
    for policy in policies:
        policy_enabled = is_true(policy.get("enabled"))
        policy_name = policy.get("name") or policy.get("id") or "unnamed-policy"
        platform = policy.get("platform_name") or "unknown-platform"
        groups = policy.get("groups") or []
        if not isinstance(groups, list):
            groups = []
        for group in groups:
            if not isinstance(group, dict):
                continue
            group_name = group.get("name") or group.get("id") or ""
            if not is_critical_group_name(group_name):
                continue
            by_platform = critical.get(group_name) or {}
            entries = by_platform.get(platform) or []
            entries.append((policy_name, policy_enabled))
            by_platform[platform] = entries
            critical[group_name] = by_platform

    disabled = []
    covered = []
    uncovered_groups = set()
    for group_name in sorted(critical):
        for platform in sorted(critical[group_name]):
            for policy_name, enabled in critical[group_name][platform]:
                if enabled:
                    covered.append(f"{policy_name} ({platform}, enabled) -> {group_name}")
                else:
                    disabled.append(f"{policy_name} ({platform}, disabled) -> {group_name}")
                    uncovered_groups.add(group_name)

    total_critical = len(critical)
    total_covered = total_critical - len(uncovered_groups)
    is_enabled_for_critical = (not api_errors) and total_critical > 0 and not disabled

    input_summary = {
        "totalPolicies": len(policies),
        "criticalHostGroupsFound": total_critical,
        "criticalHostGroupsCovered": total_covered,
        "criticalPolicyAssignments": len(covered) + len(disabled),
        "disabledCriticalAssignments": len(disabled),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append("Not measured: " + "; ".join(api_errors))
        recommendations.append(
            "Verify CrowdStrike API credentials (Prevention policies: Read) and connectivity, then re-run the scan."
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
            f"Every prevention policy assigned to the {total_critical} critical host group(s) "
            f"({', '.join(sorted(critical))}) is enabled, on every platform: " + "; ".join(covered[:10])
        )
    else:
        fail_reasons.append(
            f"{len(disabled)} prevention policy assignment(s) on critical host groups are disabled: " + "; ".join(disabled[:10])
        )
        recommendations.append(
            "Enable the listed prevention policies (or unassign them from the critical host groups) so every platform in "
            f"{', '.join(sorted(uncovered_groups))} is protected."
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
