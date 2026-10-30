"""Transformation: isBillableAssetTrackingEnabled"""
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
        assets = data
        total = len(assets)
        stats = {}
    else:
        assets = data.get("assets") or []
        total = data.get("total") or len(assets)
        stats = data.get("stats") or {}

    total_assets_seen = len(assets)
    tracked_count = 0
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        added = asset.get("bd.addedtoportfolio")
        asset_id = asset.get("id")
        if added and asset_id:
            tracked_count = tracked_count + 1

    stats_total = stats.get("total") if isinstance(stats, dict) else None

    if total_assets_seen == 0:
        is_enabled = False
        fail_reasons = ["No assets were returned by the ASM inventory endpoint (0 records), so billable asset tracking cannot be confirmed."]
        pass_reasons = []
        recommendations = ["Verify ASM connectors are configured and discovering assets; re-run once the inventory endpoint returns records."]
    else:
        coverage_ok = tracked_count == total_assets_seen
        stats_consistent = (stats_total is None) or (stats_total == total or stats_total >= total_assets_seen)
        is_enabled = bool(coverage_ok and stats_consistent)
        if is_enabled:
            pass_reasons = [
                f"All {total_assets_seen} sampled ASM inventory assets carry a non-empty bd.addedtoportfolio timestamp and unique id, "
                f"indicating each asset is tracked (billed) at creation time. Response 'total'={total} and 'stats.total'={stats_total} are consistent aggregate counts.",
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"Of {total_assets_seen} sampled assets, only {tracked_count} carry a bd.addedtoportfolio timestamp; "
                f"stats.total={stats_total} vs total={total} is inconsistent with full billable tracking.",
            ]
            recommendations = ["Investigate why some ASM-discovered assets lack a bd.addedtoportfolio timestamp; billable asset tracking should apply to every asset immediately upon creation."]

    result = {
        "isBillableAssetTrackingEnabled": is_enabled,
        "totalAssets": total,
        "trackedAssets": tracked_count,
        "sampledAssets": total_assets_seen,
    }

    input_summary = {
        "totalAssets": total,
        "sampledAssets": total_assets_seen,
        "trackedAssets": tracked_count,
        "statsTotal": stats_total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBillableAssetTrackingEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
