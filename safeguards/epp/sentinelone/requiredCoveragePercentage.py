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


def transform(input):
    data, validation = extract_input(input)

    # countAgents returns {"data": {"total": N, "decommissioned": N, "online": N, ...}}
    # extract_input leaves the raw envelope intact (does not unwrap "data")
    data = data if isinstance(data, dict) else {}

    counts = data.get("data") or {}
    if not isinstance(counts, dict):
        counts = {}

    total = counts.get("total") or 0
    decommissioned = counts.get("decommissioned") or 0
    online = counts.get("online") or 0

    # Active (non-decommissioned) agents have Endpoint Security installed
    active_agents = max(0, total - decommissioned)

    if total <= 0:
        coverage_pct = 0.0
        pass_reasons = []
        fail_reasons = [
            "No agents found in SentinelOne (data.total=0). "
            "Coverage percentage cannot be computed."
        ]
        recommendations = [
            "Enroll endpoints into SentinelOne to establish Endpoint Security coverage."
        ]
    else:
        coverage_pct = round((active_agents / float(total)) * 100.0, 2)
        if decommissioned == 0:
            pass_reasons = [
                f"All {total} enrolled agents are active (none decommissioned), "
                f"yielding {coverage_pct}% Endpoint Security coverage. "
                f"{online} of those agents are currently online."
            ]
            fail_reasons = []
            recommendations = []
        elif coverage_pct >= 90.0:
            pass_reasons = [
                f"{active_agents} of {total} enrolled agents are active "
                f"(data.total={total}, data.decommissioned={decommissioned}), "
                f"yielding {coverage_pct}% Endpoint Security coverage."
            ]
            fail_reasons = []
            recommendations = [
                f"Review the {decommissioned} decommissioned agent record(s) and remove "
                "stale entries to keep coverage metrics accurate."
            ]
        else:
            pass_reasons = []
            fail_reasons = [
                f"Only {active_agents} of {total} enrolled agents are active "
                f"(data.total={total}, data.decommissioned={decommissioned}), "
                f"yielding {coverage_pct}% Endpoint Security coverage. "
                f"{decommissioned} agents are decommissioned and no longer protected."
            ]
            recommendations = [
                f"Investigate the {decommissioned} decommissioned agent(s): re-enroll "
                "active endpoints that lost coverage, or remove stale records.",
                "Ensure all managed endpoints have the SentinelOne agent installed and active."
            ]

    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "totalAgents": total,
            "activeAgents": active_agents,
            "decommissionedAgents": decommissioned,
            "onlineAgents": online,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "total": total,
            "activeAgents": active_agents,
            "decommissioned": decommissioned,
            "online": online,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
