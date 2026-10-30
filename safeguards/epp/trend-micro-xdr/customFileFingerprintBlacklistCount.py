"""Transformation: customFileFingerprintBlacklistCount"""
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


FILE_HASH_TYPES = ["file_sha1", "file_sha256", "file_md5", "file_sha1_and_sha256"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
    else:
        items = []

    if not isinstance(items, list):
        items = []

    file_hash_items = []
    for it in items:
        if not isinstance(it, dict):
            continue
        obj_type = it.get("type") or ""
        if isinstance(obj_type, str) and obj_type.lower() in FILE_HASH_TYPES:
            file_hash_items.append(it)

    count = len(file_hash_items)
    total_items = len(items)

    if total_items == 0:
        pass_reasons = [
            "The tenant's Suspicious Object List (/v3.0/threatintel/suspiciousObjects) returned zero items, "
            "so there are zero custom file-hash blacklist entries (customFileFingerprintBlacklistCount=0)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = [
            f"Found {count} file-hash typed suspicious objects (type in {FILE_HASH_TYPES}) "
            f"out of {total_items} total suspicious objects returned."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "customFileFingerprintBlacklistCount": count,
        "totalSuspiciousObjects": total_items,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalSuspiciousObjects": total_items, "fileHashObjects": count},
        metadata={
            "transformationId": "customFileFingerprintBlacklistCount",
            "vendor": "Trend Micro XDR",
            "category": "epp",
        },
    )
