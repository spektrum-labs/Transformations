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
        stats = {}
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        total = data.get("total") or 0
        stats = data.get("stats") or {}
    else:
        assets = []
        total = 0
        stats = {}

    if not isinstance(assets, list):
        assets = []

    unmanaged_count = 0
    for a in assets:
        if not isinstance(a, dict):
            continue
        smartfolders = a.get("bd.smartfolders")
        if not smartfolders:
            unmanaged_count = unmanaged_count + 1

    sample_size = len(assets)
    total_effective = total if total else sample_size

    is_enabled = bool(total_effective and total_effective > 0 and unmanaged_count > 0)

    input_summary = {
        "totalAssets": total_effective,
        "sampledAssets": sample_size,
        "unmanagedAssetsInSample": unmanaged_count,
        "stats": stats,
    }

    if is_enabled:
        pass_reasons = [
            f"ASM inventory returned {total_effective} discovered assets in total; within the {sample_size}-asset "
            f"sample, {unmanaged_count} assets carry no bd.smartfolders classification (unclassified into any "
            "curated/managed portfolio grouping), evidencing that unmanaged and shadow-IT-candidate assets "
            "are actively discovered and surfaced outside the managed CMDB taxonomy."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"ASM inventory returned {total_effective} total assets and {unmanaged_count} unclassified "
            f"(no bd.smartfolders) assets in the {sample_size}-asset sample, which does not evidence active "
            "discovery of unmanaged/shadow-IT assets outside the managed CMDB."
        ]
        recommendations = [
            "Verify Tenable ASM discovery sources (domains, ASNs, cloud connectors) are configured and running "
            "so unmanaged internet-facing assets continue to be discovered and enumerated in the inventory."
        ]

    result = {
        "isUnmanagedAssetDiscoveryEnabled": is_enabled,
        "totalAssets": total_effective,
        "unmanagedAssetsInSample": unmanaged_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isUnmanagedAssetDiscoveryEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
