"""Transformation: staleProtectionJobsCount"""
import json
from datetime import datetime


def extract_input(input_data):
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
    if isinstance(data, list):
        nodes = data
    elif isinstance(data, dict):
        inner = data.get("data")
        if isinstance(inner, dict):
            snappable_conn = inner.get("snappableConnection")
        else:
            snappable_conn = None
        if snappable_conn is None:
            snappable_conn = data.get("snappableConnection")
        if isinstance(snappable_conn, dict):
            nodes = snappable_conn.get("nodes") or []
        elif isinstance(data.get("nodes"), list):
            nodes = data.get("nodes")

    if not isinstance(nodes, list):
        nodes = []

    total_snappables = 0
    stale_count = 0
    stale_samples = []
    transform_errors = []

    for node in nodes:
        if not isinstance(node, dict):
            continue
        total_snappables = total_snappables + 1
        missed = node.get("missedSnapshots")
        if isinstance(missed, int) and missed > 0:
            stale_count = stale_count + 1
            if len(stale_samples) < 5:
                name = node.get("name") or node.get("id") or "unknown"
                stale_samples.append(f"{name} (missedSnapshots={missed})")

    input_summary = {
        "totalSnappables": total_snappables,
        "staleProtectionJobsCount": stale_count,
    }

    if total_snappables == 0:
        pass_reasons = []
        fail_reasons = ["No snappable records were found in the response; cannot determine stale protection jobs from an empty fleet."]
        recommendations = ["Verify the getSnappables query returns protected objects for this tenant."]
    elif stale_count > 0:
        pass_reasons = []
        fail_reasons = [
            f"{stale_count} of {total_snappables} snappables have missedSnapshots > 0, indicating stale protection jobs. Examples: {', '.join(stale_samples)}."
        ]
        recommendations = [
            "Investigate the SLA Domain assignment and recent job history for the affected objects and remediate missed snapshots."
        ]
    else:
        pass_reasons = [
            f"All {total_snappables} snappables report missedSnapshots=0, indicating no stale protection jobs."
        ]
        fail_reasons = []
        recommendations = []

    return create_response(
        result={
            "staleProtectionJobsCount": stale_count,
            "totalSnappables": total_snappables,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transform_errors,
        metadata={
            "transformationId": "staleProtectionJobsCount",
            "vendor": "Rubrik Cloud Vault",
            "category": "backup",
        },
    )
