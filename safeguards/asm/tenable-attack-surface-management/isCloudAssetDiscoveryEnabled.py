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


CLOUD_KEYWORDS = [
    "aws", "amazon web services", "azure", "microsoft azure",
    "gcp", "google cloud", "google cloud platform",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        sources = data
    elif isinstance(data, dict):
        sources = data.get("sources") or data.get("searches") or data.get("data") or []
        if not isinstance(sources, list):
            sources = []
    else:
        sources = []

    total_sources = len(sources)
    cloud_sources = []
    observed_types = []

    for s in sources:
        if not isinstance(s, dict):
            continue
        type_val = s.get("type") or s.get("source_type") or s.get("search_type") or ""
        type_str = str(type_val).lower()
        if type_str:
            observed_types.append(type_str)
        is_active = True
        status_val = s.get("status")
        if status_val is not None:
            is_active = str(status_val).lower() in ("active", "enabled", "true", "1")
        if is_active:
            for kw in CLOUD_KEYWORDS:
                if kw in type_str:
                    cloud_sources.append(s)
                    break

    is_cloud_enabled = len(cloud_sources) > 0

    unique_types = []
    for t in observed_types:
        if t not in unique_types:
            unique_types.append(t)

    input_summary = {
        "totalSources": total_sources,
        "cloudSourceCount": len(cloud_sources),
        "observedTypes": unique_types,
    }

    if is_cloud_enabled:
        pass_reasons = [
            f"Found {len(cloud_sources)} active source(s) with a cloud-connector type among {total_sources} total sources: types observed {unique_types}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_sources} configured sources carry an AWS/Azure/GCP cloud-connector type; observed types were {unique_types if unique_types else 'none'} (e.g. domain-based DNS searches), indicating discovery relies on DNS-based enumeration rather than dedicated cloud connectors."
        ]
        recommendations = [
            "Configure a dedicated cloud connector (AWS, Azure, or GCP) in Tenable ASM's Integrations/Sources settings to enable cloud-native asset discovery beyond DNS enumeration."
        ]

    result = {
        "isCloudAssetDiscoveryEnabled": is_cloud_enabled,
        "totalSources": total_sources,
        "cloudSourceCount": len(cloud_sources),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isCloudAssetDiscoveryEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
