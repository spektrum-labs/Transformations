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
        domains = data
        total_results = len(domains)
    elif isinstance(data, dict):
        domains = data.get("domains") or []
        total_results = data.get("total_results")
        if not isinstance(total_results, int):
            total_results = len(domains)
    else:
        domains = []
        total_results = 0

    if not isinstance(domains, list):
        domains = []

    total_domains = len(domains)
    primary_count = 0
    non_primary_count = 0
    for d in domains:
        if not isinstance(d, dict):
            continue
        if d.get("primary_domain"):
            primary_count = primary_count + 1
        else:
            non_primary_count = non_primary_count + 1

    is_enabled = bool(total_domains > 1 and non_primary_count > 0)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"getDomains returned {total_domains} monitored hostnames (total_results={total_results}), "
            f"of which {non_primary_count} are non-primary/auto-discovered subdomains "
            f"(e.g. beyond the {primary_count} primary domain(s)), demonstrating the platform's "
            f"discovery engine surfaces shadow/unmanaged subdomains automatically."
        )
    else:
        fail_reasons.append(
            f"getDomains returned {total_domains} hostnames with {non_primary_count} non-primary entries "
            f"(primary_domain count={primary_count}); no evidence of auto-discovered shadow subdomains beyond "
            f"the registered primary domain(s)."
        )
        recommendations.append(
            "Enable UpGuard's automated domain/subdomain discovery for this account so unmanaged "
            "or shadow assets are surfaced under the Domains view."
        )

    result = {
        "isUnmanagedAssetDiscoveryEnabled": is_enabled,
        "totalDomains": total_domains,
        "primaryDomains": primary_count,
        "nonPrimaryDomains": non_primary_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDomains": total_domains, "nonPrimaryDomains": non_primary_count, "totalResults": total_results},
        metadata={
            "transformationId": "isUnmanagedAssetDiscoveryEnabled",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
