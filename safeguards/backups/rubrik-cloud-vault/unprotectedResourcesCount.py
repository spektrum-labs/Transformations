
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    nodes = []
    total_count = None

    if isinstance(data, list):
        nodes = data
    elif isinstance(data, dict):
        # Unwrap GraphQL 'data' envelope if still present after extract_input
        gql_data = data.get("data")
        if isinstance(gql_data, dict):
            data = gql_data
        conn = data.get("snappableConnection")
        if isinstance(conn, dict):
            nodes = conn.get("nodes") or []
            total_count = conn.get("count")
        else:
            nodes = data.get("nodes") or []
        if total_count is None:
            pagination = data.get("pagination") or {}
            total_count = pagination.get("totalItems")

    nodes = nodes if isinstance(nodes, list) else []

    unprotected = 0
    protected = 0
    unknown_status = 0
    unprotected_samples = []

    for node in nodes:
        if not isinstance(node, dict):
            continue
        status = node.get("protectionStatus")
        sla = node.get("slaDomain")
        has_sla = bool(sla) if isinstance(sla, dict) and sla.get("id") else False
        if status is None:
            unknown_status = unknown_status + 1
            continue
        if status == "Protected" or has_sla:
            protected = protected + 1
        else:
            unprotected = unprotected + 1
            if len(unprotected_samples) < 5:
                unprotected_samples.append({
                    "id": node.get("id"),
                    "name": node.get("name"),
                    "objectType": node.get("objectType"),
                    "protectionStatus": status,
                })

    scanned = len(nodes)

    fail_reasons = []
    pass_reasons = []
    recommendations = []

    if scanned == 0:
        fail_reasons.append(
            "No snappable records were returned by getSnappables; unable to determine unprotected resource count."
        )
        recommendations.append("Verify the getSnappables query is returning data for this tenant.")
    else:
        sample_desc_parts = []
        for s in unprotected_samples:
            sample_desc_parts.append(f"{s.get('name')} ({s.get('objectType')}, protectionStatus={s.get('protectionStatus')})")
        sample_desc = "; ".join(sample_desc_parts) if sample_desc_parts else "none"

        if unprotected > 0:
            fail_reasons.append(
                f"{unprotected} of {scanned} scanned snappables have protectionStatus != 'Protected' and no slaDomain assigned. "
                f"Examples: {sample_desc}."
            )
            recommendations.append(
                "Assign an SLA Domain to the unprotected resources identified above to bring them under a backup protection policy."
            )
        else:
            pass_reasons.append(
                f"All {scanned} scanned snappables report protectionStatus='Protected' with an assigned slaDomain; "
                f"0 unprotected resources found out of {scanned} scanned (fleet total reported: {total_count})."
            )

    result = {
        "unprotectedResourcesCount": unprotected,
        "protectedResourcesCount": protected,
        "scannedResourcesCount": scanned,
        "totalResourcesReported": total_count if total_count is not None else scanned,
        "unknownStatusCount": unknown_status,
    }

    input_summary = {
        "scannedResourcesCount": scanned,
        "unprotectedResourcesCount": unprotected,
        "protectedResourcesCount": protected,
        "totalResourcesReported": total_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "unprotectedResourcesCount",
            "vendor": "Rubrik Cloud Vault",
            "category": "backup",
        },
    )
