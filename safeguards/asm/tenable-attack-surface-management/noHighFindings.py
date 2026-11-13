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
        reported_total = len(assets)
    elif isinstance(data, dict):
        assets = data.get("assets") or []
        if not isinstance(assets, list):
            assets = []
        reported_total = data.get("total")
        if not isinstance(reported_total, int):
            reported_total = len(assets)
    else:
        assets = []
        reported_total = 0

    high_severity_assets = []
    for a in assets:
        if not isinstance(a, dict):
            continue
        sev = a.get("bd.severity_ranking")
        if isinstance(sev, str) and sev.lower() == "high":
            high_severity_assets.append(a)

    high_count = len(high_severity_assets)
    scanned_count = len(assets)
    no_high_findings = high_count == 0

    sample_hostnames = [
        a.get("bd.hostname") or a.get("bd.original_hostname") or a.get("id")
        for a in high_severity_assets[:5]
    ]

    input_summary = {
        "scannedAssets": scanned_count,
        "reportedTotalAssets": reported_total,
        "highSeverityAssetCount": high_count,
    }

    if no_high_findings:
        pass_reasons = [
            f"Scanned {scanned_count} inventory assets (reported total {reported_total}) "
            f"and found 0 assets with bd.severity_ranking='high'."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {high_count} assets with bd.severity_ranking='high' out of "
            f"{scanned_count} scanned (reported total {reported_total}). "
            f"Examples: {sample_hostnames}."
        ]
        recommendations = [
            "Triage and remediate the high-severity findings listed in the ASM inventory, "
            "or reclassify them via smart folders/portfolio assignment if not applicable."
        ]

    result = {
        "noHighFindings": no_high_findings,
        "highSeverityAssetCount": high_count,
        "scannedAssetCount": scanned_count,
        "reportedTotalAssets": reported_total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "noHighFindings",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
