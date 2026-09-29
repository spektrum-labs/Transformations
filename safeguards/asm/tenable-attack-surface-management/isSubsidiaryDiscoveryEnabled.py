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
        stats = {}
        total = len(assets)
    else:
        assets = data.get("assets") or []
        if not isinstance(assets, list):
            assets = []
        stats = data.get("stats") or {}
        if not isinstance(stats, dict):
            stats = {}
        total = data.get("total")
        if not isinstance(total, int):
            total = len(assets)

    domain_count = stats.get("domaincount")
    if not isinstance(domain_count, int):
        domain_count = None

    distinct_root_domains = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        root = asset.get("bd.original_hostname")
        if root and root not in distinct_root_domains:
            distinct_root_domains.append(root)

    if domain_count is not None:
        effective_domain_count = domain_count
        source_note = "stats.domaincount"
    else:
        effective_domain_count = len(distinct_root_domains)
        source_note = "distinct bd.original_hostname values in sample"

    is_subsidiary_discovery_enabled = effective_domain_count > 1

    input_summary = {
        "totalAssets": total,
        "domainCount": effective_domain_count,
        "sampleDistinctRootDomains": distinct_root_domains[:10],
        "domainCountSource": source_note,
    }

    if is_subsidiary_discovery_enabled:
        pass_reasons = [
            "Inventory stats report %d distinct domains (%s) across %d discovered assets, "
            "indicating ASM has attributed internet-facing assets to more than a single "
            "parent domain, evidencing subsidiary/related-domain discovery."
            % (effective_domain_count, source_note, total)
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Inventory stats report only %d domain(s) (%s) across %d discovered assets, "
            "indicating ASM inventory is scoped to a single parent domain with no "
            "subsidiary/related-domain attribution detected."
            % (effective_domain_count, source_note, total)
        ]
        recommendations = [
            "Configure additional root domain searches for known subsidiary organizations "
            "so ASM can discover and attribute their internet-facing assets separately "
            "from the parent domain."
        ]

    result = {
        "isSubsidiaryDiscoveryEnabled": is_subsidiary_discovery_enabled,
        "domainCount": effective_domain_count,
        "totalAssets": total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSubsidiaryDiscoveryEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
