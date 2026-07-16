"""Transformation: requiredCoveragePercentage — SentinelOne getAgents
Coverage percentage of endpoints which Endpoint Security is installed.
Uses fully-paginated agent list (follow=true, max_pages=null) so len(items)
equals fleet-wide total.

Coverage counts every enrolled agent that is still installed (not uninstalled
and not decommissioned). It deliberately does NOT gate on isActive: in
SentinelOne isActive reflects only a recent management-console check-in/online
session, so it is false for asleep, offline, or roaming endpoints that remain
fully installed and protected (activeProtection still [edr], mitigationMode
still protect/detect). Gating coverage on isActive understates protection and
produced false "low coverage" failures — e.g. UFT reported 265/919 = 28.84%
while the isEPPConfigured / isEPPEnabled checks found all 919 agents installed
and in an enforcing mitigation mode.
"""

import json
from datetime import datetime


def _as_bool(value):
    """Coerce a SentinelOne boolean-ish field to a real bool.

    The agent payload may carry native booleans or the strings 'true'/'false'
    depending on the collection path; naive truthiness treats the string
    'False' as True, so normalize explicitly.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


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


def transform(input):
    data, validation = extract_input(input)

    # Token-Service preprocessing may unwrap to a bare list of agents (when API
    # response's `data` field is a list) or leave a dict containing `data`.
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    # With follow=true and max_pages=null, the runtime aggregates all pages into data.
    # len(items) is the fleet-wide enrolled count — same scope as our per-agent counts.
    total_enrolled = len(items)

    installed_count = 0
    uninstalled_count = 0
    decommissioned_count = 0
    inactive_installed_count = 0

    for agent in items:
        if not isinstance(agent, dict):
            continue
        if _as_bool(agent.get("isUninstalled")):
            uninstalled_count = uninstalled_count + 1
            continue
        if _as_bool(agent.get("isDecommissioned")):
            decommissioned_count = decommissioned_count + 1
            continue
        # Enrolled and neither uninstalled nor decommissioned => Endpoint
        # Security IS installed on this endpoint, which is what this metric
        # measures. Do NOT gate on isActive (see module docstring): it only
        # tracks a recent console check-in and flips to false for offline but
        # still-protected endpoints.
        installed_count = installed_count + 1
        is_active = agent.get("isActive")
        if is_active is not None and not _as_bool(is_active):
            inactive_installed_count = inactive_installed_count + 1

    covered_count = installed_count

    if total_enrolled > 0:
        coverage_pct = round((covered_count / total_enrolled) * 100, 2)
    else:
        coverage_pct = 0.0

    not_covered = total_enrolled - covered_count

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_enrolled == 0:
        fail_reasons.append(
            "No enrolled agents found in the SentinelOne account. "
            "Endpoint Security coverage cannot be determined."
        )
        recommendations.append(
            "Deploy the SentinelOne agent to managed endpoints and enroll them in the console."
        )
    elif coverage_pct >= 100.0:
        pass_reasons.append(
            f"All {total_enrolled} enrolled endpoints have the SentinelOne agent installed "
            f"(isUninstalled=false, isDecommissioned=false), yielding 100% Endpoint Security coverage."
        )
    else:
        fail_reasons.append(
            f"{covered_count} of {total_enrolled} enrolled endpoints have the SentinelOne agent "
            f"installed ({coverage_pct}% coverage); {uninstalled_count} are uninstalled and "
            f"{decommissioned_count} are decommissioned, leaving {not_covered} endpoint(s) without "
            f"Endpoint Security installed."
        )
        recommendations.append(
            f"Redeploy the SentinelOne agent to the {not_covered} endpoint(s) that are uninstalled "
            f"or decommissioned to restore full coverage."
        )

    additional_findings = []
    if uninstalled_count > 0:
        additional_findings.append(
            f"{uninstalled_count} agent(s) have isUninstalled=true and are excluded from the coverage count."
        )
    if decommissioned_count > 0:
        additional_findings.append(
            f"{decommissioned_count} agent(s) have isDecommissioned=true and are excluded from the coverage count."
        )
    if inactive_installed_count > 0:
        additional_findings.append(
            f"{inactive_installed_count} installed agent(s) have isActive=false (no recent console "
            f"check-in). They remain installed and are counted as covered, but are worth reviewing — "
            f"investigate any that have not reported for an extended period as they may be stale records."
        )

    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "installedAgents": covered_count,
            # activeAgents retained for backward compatibility; now equals the
            # installed/covered count (no longer gated on isActive).
            "activeAgents": covered_count,
            "inactiveAgents": inactive_installed_count,
            "totalEnrolledAgents": total_enrolled,
            "uninstalledAgents": uninstalled_count,
            "decommissionedAgents": decommissioned_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalEnrolledAgents": total_enrolled,
            "installedAgents": covered_count,
            "activeAgents": covered_count,
            "inactiveAgents": inactive_installed_count,
            "uninstalledAgents": uninstalled_count,
            "decommissionedAgents": decommissioned_count,
            "coveragePercentage": coverage_pct,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
