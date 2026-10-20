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

    if isinstance(data, list):
        assets = data
        total = len(assets)
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        if not isinstance(assets, list):
            assets = []
        total = data.get("total")
        if not isinstance(total, int):
            total = len(assets)
    else:
        assets = []
        total = 0

    unmanaged_count = 0
    managed_count = 0
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        added = asset.get("bd.addedtoportfolio")
        if added is None or added == 0 or added is False:
            unmanaged_count = unmanaged_count + 1
        else:
            managed_count = managed_count + 1

    sample_size = len(assets)
    is_enabled = total > 0 and unmanaged_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"Inventory returned {total} discovered assets (sample of {sample_size} inspected); "
            f"{unmanaged_count} of the sampled assets carry no bd.addedtoportfolio value, "
            f"indicating ASM discovers assets outside the managed CMDB/portfolio."
        )
    else:
        if total == 0:
            fail_reasons.append("Inventory returned zero assets, so unmanaged asset discovery cannot be evidenced.")
            recommendations.append("Verify ASM connectors/sources are configured to populate the inventory.")
        else:
            fail_reasons.append(
                f"All {managed_count} of {sample_size} sampled assets (of {total} total) carry a "
                f"non-zero bd.addedtoportfolio value, indicating every discovered asset is already "
                f"claimed into the managed portfolio and no unmanaged/shadow-IT assets were found."
            )
            recommendations.append(
                "Confirm ASM is scanning broadly enough to surface unclaimed shadow-IT assets, "
                "or review bd.addedtoportfolio semantics for this tenant."
            )

    result = {
        "isUnmanagedAssetDiscoveryEnabled": is_enabled,
        "totalAssets": total,
        "unmanagedAssetCount": unmanaged_count,
        "managedAssetCount": managed_count,
        "sampleSize": sample_size,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAssets": total,
            "sampleSize": sample_size,
            "unmanagedAssetCount": unmanaged_count,
            "managedAssetCount": managed_count,
        },
        metadata={
            "transformationId": "isUnmanagedAssetDiscoveryEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
