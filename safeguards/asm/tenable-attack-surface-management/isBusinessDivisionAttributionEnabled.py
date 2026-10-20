
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
        total = data.get("total") or len(assets)
    else:
        assets = []
        total = 0

    scanned = len(assets)

    attributed_count = 0
    bd_field_present_count = 0

    for a in assets:
        if not isinstance(a, dict):
            continue
        smartfolders = a.get("bd.smartfolders")
        original_hostname = a.get("bd.original_hostname")
        severity_ranking = a.get("bd.severity_ranking")

        has_bd_fields = bool(original_hostname) or bool(severity_ranking)
        if has_bd_fields:
            bd_field_present_count = bd_field_present_count + 1

        if isinstance(smartfolders, str) and smartfolders.strip() != "":
            attributed_count = attributed_count + 1
        elif isinstance(smartfolders, list) and len(smartfolders) > 0:
            attributed_count = attributed_count + 1

    is_enabled = attributed_count > 0

    input_summary = {
        "scannedAssets": scanned,
        "totalAssets": total,
        "assetsWithBdFields": bd_field_present_count,
        "assetsWithSmartfolderAttribution": attributed_count,
    }

    if is_enabled:
        pass_reasons = [
            f"{attributed_count} of {scanned} scanned inventory assets carry a non-empty bd.smartfolders "
            f"value, evidencing business-division/portfolio attribution is actively assigned to assets."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {scanned} scanned inventory assets (total reported: {total}) carry a non-empty "
            f"bd.smartfolders value -- all {scanned} records have bd.smartfolders == '' even though "
            f"bd.original_hostname and bd.severity_ranking are populated on {bd_field_present_count} assets. "
            f"Smart folders are the ASM mechanism for organizing assets by business unit, and none are assigned."
        ]
        recommendations = [
            "Create and assign smart folders (or portfolios) per business division in Tenable ASM so that "
            "bd.smartfolders is populated on inventory assets, enabling business-division attribution reporting."
        ]

    result = {
        "isBusinessDivisionAttributionEnabled": is_enabled,
        "totalAssets": total,
        "assetsWithBdAttribution": attributed_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBusinessDivisionAttributionEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
