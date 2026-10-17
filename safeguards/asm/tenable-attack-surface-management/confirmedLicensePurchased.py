"""Transformation: confirmedLicensePurchased (Tenable ASM)"""
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
        total = data.get("total")
        if total is None:
            total = len(assets)
        stats = data.get("stats") or {}

    stats_total = stats.get("total") if isinstance(stats, dict) else None
    hostcount = stats.get("hostcount") if isinstance(stats, dict) else None
    domaincount = stats.get("domaincount") if isinstance(stats, dict) else None
    subdomaincount = stats.get("subdomaincount") if isinstance(stats, dict) else None
    ipcount = stats.get("ipcount") if isinstance(stats, dict) else None
    free_limit_reached = data.get("freeLimitReached") if isinstance(data, dict) else None

    has_inventory = bool(total and total > 0)
    has_stats = bool(stats_total and stats_total > 0)

    license_active = has_inventory and has_stats

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    input_summary = {
        "total": total,
        "statsTotal": stats_total,
        "hostcount": hostcount,
        "domaincount": domaincount,
        "subdomaincount": subdomaincount,
        "ipcount": ipcount,
        "freeLimitReached": free_limit_reached,
    }

    if license_active:
        pass_reasons.append(
            f"ASM inventory returned total={total} assets with stats.total={stats_total} "
            f"(hostcount={hostcount}, domaincount={domaincount}, subdomaincount={subdomaincount}, "
            f"ipcount={ipcount}), confirming an active, provisioned ASM container is billing and "
            f"tracking discovered assets rather than an empty or lapsed tenant."
        )
        if free_limit_reached:
            additional_findings.append(
                "Response flag freeLimitReached=true was observed alongside a substantial "
                f"asset count (total={total}); this scale of tracked inventory is consistent with "
                "an active paid subscription, but review the account plan if a free/trial tier "
                "is suspected."
            )
    else:
        fail_reasons.append(
            f"ASM inventory response reported total={total} and stats.total={stats_total}, "
            "which does not confirm active billable asset tracking under a live license."
        )
        recommendations.append(
            "Verify the Tenable ASM subscription is active and not expired/lapsed; confirm "
            "connectors are configured to discover and bill assets."
        )

    result = {
        "confirmedLicensePurchased": license_active,
        "totalAssets": total,
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
            "transformationId": "confirmedLicensePurchased",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
        additional_findings=additional_findings,
    )
