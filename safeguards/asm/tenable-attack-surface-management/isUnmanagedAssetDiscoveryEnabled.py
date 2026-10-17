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
        total_field = data.get("total")
        total = total_field if isinstance(total_field, int) else len(assets)
        stats = data.get("stats") or {}

    # Unmanaged / shadow-IT proxy: assets discovered by ASM that are not
    # placed into a managed smart folder / portfolio grouping (bd.smartfolders
    # empty) - i.e. discovered outside of the tracked/managed CMDB grouping.
    unmanaged_count = 0
    for a in assets:
        if not isinstance(a, dict):
            continue
        smartfolders = a.get("bd.smartfolders")
        if smartfolders is None or smartfolders == "" or smartfolders == []:
            unmanaged_count = unmanaged_count + 1

    hostcount = stats.get("hostcount") if isinstance(stats, dict) else None
    ipcount = stats.get("ipcount") if isinstance(stats, dict) else None
    domaincount = stats.get("domaincount") if isinstance(stats, dict) else None
    subdomaincount = stats.get("subdomaincount") if isinstance(stats, dict) else None

    is_enabled = total > 0 and unmanaged_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"ASM inventory returned {total} total discovered assets, of which {unmanaged_count} carry no smart-folder/portfolio assignment (bd.smartfolders empty), evidencing internet-facing assets discovered outside a managed CMDB grouping."
        )
        if isinstance(stats, dict) and stats:
            pass_reasons.append(
                f"Inventory stats: hostcount={hostcount}, domaincount={domaincount}, subdomaincount={subdomaincount}, ipcount={ipcount} - discovery spans hosts, domains, subdomains and IPs beyond a fixed managed asset list."
            )
    else:
        if total == 0:
            fail_reasons.append("ASM inventory response returned total=0 assets; no discovery activity evidenced.")
            recommendations.append("Verify the ASM container is provisioned and discovery sources are configured to populate the inventory.")
        else:
            fail_reasons.append(
                f"ASM inventory returned {total} assets but all {total - unmanaged_count} of them carry a non-empty bd.smartfolders assignment, so no evidence of unmanaged/untagged discovered assets was found."
            )
            recommendations.append("Confirm that ASM discovery is surfacing assets outside the managed/tagged smart-folder set (e.g. newly discovered shadow-IT hosts) rather than only pre-classified assets.")

    result = {
        "isUnmanagedAssetDiscoveryEnabled": is_enabled,
        "totalAssets": total,
        "unmanagedAssetCount": unmanaged_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalAssets": total, "unmanagedAssetCount": unmanaged_count, "stats": stats},
        metadata={
            "transformationId": "isUnmanagedAssetDiscoveryEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
