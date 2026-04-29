
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
    data = data if isinstance(data, dict) else {}

    items = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    # Count agents in the sample with active protection entries
    agents_with_protection = 0
    protection_names = []
    for agent in items:
        if isinstance(agent, dict):
            ap = agent.get("activeProtection") or []
            if ap:
                agents_with_protection = agents_with_protection + 1
                for p in ap:
                    if p not in protection_names:
                        protection_names.append(p)

    is_epp_enabled = total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_epp_enabled:
        prot_str = ", ".join(protection_names) if protection_names else "not captured in sample"
        pass_reasons.append(
            f"SentinelOne reports {total_items} enrolled agents (pagination.totalItems={total_items}), "
            f"confirming EPP is deployed across the fleet."
        )
        if agents_with_protection > 0:
            pass_reasons.append(
                f"{agents_with_protection} of {len(items)} sampled agents have activeProtection entries: [{prot_str}], "
                f"indicating active endpoint protection modules are running."
            )
    else:
        fail_reasons.append(
            "No enrolled agents found (pagination.totalItems=0). "
            "EPP cannot be considered enabled if no agents are deployed."
        )
        recommendations.append(
            "Deploy the SentinelOne agent to endpoints to establish EPP coverage. "
            "Verify that the API token has sufficient scope to read agent data."
        )

    return create_response(
        result={
            "isEPPEnabled": is_epp_enabled,
            "totalAgents": total_items,
            "sampledAgents": len(items),
            "sampledAgentsWithActiveProtection": agents_with_protection,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalItems": total_items,
            "sampleSize": len(items),
            "agentsWithActiveProtection": agents_with_protection,
        },
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
