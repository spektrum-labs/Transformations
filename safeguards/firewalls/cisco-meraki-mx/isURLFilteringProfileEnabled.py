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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    blocked_categories = data.get("blockedUrlCategories") or []
    blocked_patterns = data.get("blockedUrlPatterns") or []
    allowed_patterns = data.get("allowedUrlPatterns") or []
    url_category_list_size = data.get("urlCategoryListSize")

    blocked_categories = blocked_categories if isinstance(blocked_categories, list) else []
    blocked_patterns = blocked_patterns if isinstance(blocked_patterns, list) else []
    allowed_patterns = allowed_patterns if isinstance(allowed_patterns, list) else []

    blocked_categories_count = len(blocked_categories)
    blocked_patterns_count = len(blocked_patterns)

    is_enabled = blocked_categories_count > 0 or blocked_patterns_count > 0

    input_summary = {
        "blockedUrlCategoriesCount": blocked_categories_count,
        "blockedUrlPatternsCount": blocked_patterns_count,
        "allowedUrlPatternsCount": len(allowed_patterns),
        "urlCategoryListSize": url_category_list_size,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"Content filtering profile has {blocked_categories_count} blocked URL categories and "
            f"{blocked_patterns_count} blocked URL patterns configured (urlCategoryListSize={url_category_list_size})."
        )
    else:
        fail_reasons.append(
            "Content filtering profile has zero blockedUrlCategories and zero blockedUrlPatterns configured, "
            "indicating an empty or default (non-active) URL filtering profile."
        )
        recommendations.append(
            "Configure blockedUrlCategories (and/or blockedUrlPatterns) on the network's appliance content "
            "filtering profile to actively enforce URL filtering."
        )

    result = {
        "isURLFilteringProfileEnabled": is_enabled,
        "blockedUrlCategoriesCount": blocked_categories_count,
        "blockedUrlPatternsCount": blocked_patterns_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isURLFilteringProfileEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
