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

    # getOrganizations returns a columnar (struct-of-arrays) shape:
    # {"id": [...], "name": [...], "nodeCount": [...], ...}
    org_ids = data.get("id") or []
    org_names = data.get("name") or []
    node_counts = data.get("nodeCount") or []

    if not isinstance(org_ids, list):
        org_ids = []
    if not isinstance(node_counts, list):
        node_counts = []
    if not isinstance(org_names, list):
        org_names = []

    total_orgs = len(org_ids)
    total_nodes = 0
    orgs_with_nodes = 0
    sample_org_names = []

    idx = 0
    while idx < len(node_counts):
        raw_count = node_counts[idx]
        count = raw_count if isinstance(raw_count, (int, float)) else 0
        total_nodes = total_nodes + count
        if count > 0:
            orgs_with_nodes = orgs_with_nodes + 1
            if idx < len(org_names) and len(sample_org_names) < 3:
                sample_org_names.append(org_names[idx])
        idx = idx + 1

    is_deployed = total_nodes > 0

    input_summary = {
        "totalOrganizations": total_orgs,
        "organizationsWithNodes": orgs_with_nodes,
        "totalNodeCount": total_nodes,
    }

    if is_deployed:
        pass_reasons = [
            f"Found {total_nodes} total device(s) (nodeCount) across {orgs_with_nodes} of {total_orgs} organization(s), indicating the NinjaOne agent is installed and reporting."
        ]
        if sample_org_names:
            pass_reasons.append(
                f"Organizations with enrolled devices include: {', '.join([str(n) for n in sample_org_names])}."
            )
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No organizations report a positive nodeCount ({total_orgs} organization(s) inspected, totalNodeCount={total_nodes}), indicating no NinjaOne agents are currently enrolled/communicating."
        ]
        recommendations = [
            "Deploy the NinjaOne agent installer to at least one endpoint and confirm it completes enrollment (approvalStatus=APPROVED) and reports online status."
        ]

    result = {
        "isAgentDeployed": is_deployed,
        "totalNodeCount": total_nodes,
        "organizationsWithNodes": orgs_with_nodes,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAgentDeployed",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
