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
        models = data
    elif isinstance(data, dict):
        models = data.get("data") or []
        if not isinstance(models, list):
            models = []
    else:
        models = []

    ransomware_keywords = ["ransomware", "folder shield", "anti-ransomware", "antiransomware"]

    matched_models = []
    for m in models:
        if not isinstance(m, dict):
            continue
        name = m.get("name") or ""
        name_lower = name.lower()
        for kw in ransomware_keywords:
            if kw in name_lower:
                matched_models.append(m)
                break

    total_models = len(models)
    matched_count = len(matched_models)
    enabled_matches = [m for m in matched_models if m.get("enabled") is True]
    is_enabled = len(enabled_matches) > 0

    matched_names = [m.get("name") for m in matched_models][:10]
    enabled_names = [m.get("name") for m in enabled_matches][:10]

    if matched_count == 0:
        fail_reasons = [
            f"No detection model name among {total_models} models scanned from listDetectionModels "
            f"matched ransomware-related keywords ({', '.join(ransomware_keywords)})."
        ]
        recommendations = [
            "Verify Trend Micro Vision One has a ransomware/folder-shield behavioral detection model enabled, "
            "and confirm the Detection Models API exposes it under a name containing 'ransomware'."
        ]
        pass_reasons = []
    elif is_enabled:
        pass_reasons = [
            f"Found {matched_count} ransomware-related detection model(s) among {total_models} total models; "
            f"{len(enabled_matches)} are enabled=true (examples: {enabled_names})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Found {matched_count} ransomware-related detection model(s) (examples: {matched_names}) "
            f"among {total_models} total models, but none have enabled=true."
        ]
        recommendations = [
            "Enable the ransomware/behavior-based detection model(s) listed above in the Detection Model Management console."
        ]

    result = {
        "isRansomwareDetectionEnabled": is_enabled,
        "totalDetectionModels": total_models,
        "ransomwareModelMatchCount": matched_count,
        "ransomwareModelEnabledCount": len(enabled_matches),
    }

    input_summary = {
        "totalDetectionModels": total_models,
        "matchedModelNames": matched_names,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isRansomwareDetectionEnabled",
            "vendor": "Trend Micro XDR",
            "category": "epp",
        },
    )
