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

    if isinstance(data, list):
        items = data
        reported_total = len(items)
    elif isinstance(data, dict):
        items = data.get("assets") or []
        if not isinstance(items, list):
            items = []
        reported_total = data.get("total")
        if not isinstance(reported_total, int):
            reported_total = len(items)
    else:
        items = []
        reported_total = 0

    backlog_items = []
    for asset in items:
        if not isinstance(asset, dict):
            continue
        added_to_portfolio = asset.get("bd.addedtoportfolio")
        if not added_to_portfolio:
            backlog_items.append(asset)

    backlog_count = len(backlog_items)
    total_scanned = len(items)

    sample_ids = [a.get("id") for a in backlog_items[:5] if isinstance(a, dict)]

    input_summary = {
        "totalAssetsScanned": total_scanned,
        "reportedInventoryTotal": reported_total,
        "backlogCount": backlog_count,
    }

    if total_scanned == 0:
        pass_reasons = []
        fail_reasons = [
            "No inventory assets were returned by listInventoryAssets (assets list is empty); "
            "backlog count could not be derived from any asset records."
        ]
        recommendations = [
            "Verify the ASM inventory API is returning asset records for this tenant before relying on this metric."
        ]
    elif backlog_count > 0:
        pass_reasons = [
            f"Found {backlog_count} of {total_scanned} inventory assets with bd.addedtoportfolio unset "
            f"(0/falsy), indicating they have been discovered but not yet confirmed/triaged into the portfolio. "
            f"Sample untriaged asset ids: {sample_ids}."
        ]
        fail_reasons = []
        recommendations = [
            "Review the untriaged assets in Tenable ASM inventory and confirm or reject them to reduce backlog."
        ]
    else:
        pass_reasons = [
            f"All {total_scanned} inventory assets have a non-zero bd.addedtoportfolio timestamp, "
            f"indicating none are awaiting triage."
        ]
        fail_reasons = []
        recommendations = []

    return create_response(
        result={
            "assetTriageBacklogCount": backlog_count,
            "totalAssetsScanned": total_scanned,
            "reportedInventoryTotal": reported_total,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "assetTriageBacklogCount",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
