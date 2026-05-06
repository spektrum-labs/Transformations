"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: SentinelOne
Category: epp
Method: getEndpoints

Confirms EPP coverage on systems classified as "critical." SentinelOne does not
have a built-in "critical" tag, so we proxy critical-system identity by
machineType=='server'. (Customers that classify critical systems differently —
via groupName or tags — should refine this transformation.)

Pass logic:
  - If servers are present in the fleet, ALL servers must have active EPP
    (mitigationMode in protect/detect AND activeProtection populated).
  - If no servers are present in the fleet, pass with an additional finding
    noting that no critical systems were identified — endpoint coverage is
    evaluated separately by isEPPEnabled / isEPPDeployed.
"""
import json
from datetime import datetime, timezone


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
        "evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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


def _is_critical(agent):
    """Heuristic for 'critical system' — currently machineType == 'server'."""
    machine_type = (agent.get("machineType") or "").lower() if isinstance(agent.get("machineType"), str) else ""
    return machine_type == "server"


def _is_protected(agent):
    """An agent is considered EPP-protected when mitigation is active and protection modules are reporting."""
    mitigation = agent.get("mitigationMode") or ""
    active_protection = agent.get("activeProtection") or []
    if not isinstance(active_protection, list):
        active_protection = []
    return mitigation in ("protect", "detect") and len(active_protection) > 0


def transform(input):
    data, validation = extract_input(input)

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    total = len(items)
    critical_systems = [a for a in items if isinstance(a, dict) and _is_critical(a)]
    critical_count = len(critical_systems)
    unprotected_critical = [a for a in critical_systems if not _is_protected(a)]
    unprotected_names = [
        a.get("computerName") or a.get("uuid") or "unknown" for a in unprotected_critical[:5]
    ]

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if total == 0:
        return create_response(
            result={
                "isEPPEnabledForCriticalSystems": False,
                "criticalSystemsTotal": 0,
                "criticalSystemsProtected": 0,
                "criticalSystemsUnprotected": 0,
                "fleetTotal": 0,
            },
            validation=validation,
            fail_reasons=[
                "No enrolled agents found for the configured site — cannot evaluate EPP on critical systems."
            ],
            recommendations=["Deploy SentinelOne agents to managed endpoints, then re-evaluate."],
            input_summary={"fleetTotal": 0, "criticalSystemsTotal": 0},
            metadata={
                "transformationId": "isEPPEnabledForCriticalSystems",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    if critical_count == 0:
        # No servers in the fleet; pass with a finding so reviewers understand the scope.
        additional_findings.append(
            f"No critical systems (machineType='server') were identified in the fleet of "
            f"{total} agents. Either no servers are managed by SentinelOne, or critical "
            f"classification needs a different heuristic (e.g. tag or groupName)."
        )
        pass_reasons.append(
            "No critical systems identified — vacuously passes. EPP coverage on endpoints "
            "is evaluated separately by isEPPEnabled / isEPPDeployed."
        )
        is_pass = True
    elif len(unprotected_critical) == 0:
        is_pass = True
        pass_reasons.append(
            f"All {critical_count} critical system(s) (machineType='server') have EPP "
            f"actively protecting them (mitigationMode in protect/detect, activeProtection populated)."
        )
    else:
        is_pass = False
        fail_reasons.append(
            f"{len(unprotected_critical)} of {critical_count} critical systems are not "
            f"protected by EPP (e.g. {', '.join(unprotected_names)})."
        )
        recommendations.append(
            "Verify EPP policy on identified servers. Set mitigationMode to 'protect' or 'detect' "
            "and ensure activeProtection modules (edr, etc.) are enabled in the agent policy."
        )

    return create_response(
        result={
            "isEPPEnabledForCriticalSystems": is_pass,
            "criticalSystemsTotal": critical_count,
            "criticalSystemsProtected": critical_count - len(unprotected_critical),
            "criticalSystemsUnprotected": len(unprotected_critical),
            "fleetTotal": total,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "fleetTotal": total,
            "criticalSystemsTotal": critical_count,
            "criticalSystemsProtected": critical_count - len(unprotected_critical),
            "criticalSystemsUnprotected": len(unprotected_critical),
        },
        metadata={
            "transformationId": "isEPPEnabledForCriticalSystems",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
