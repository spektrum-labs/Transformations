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


PATCH_KEYWORDS = ["patch", "softwarePatchManagement", "osPatchManagement", "patchManagement"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("data") or []
        if not isinstance(records, list):
            records = []
    else:
        records = []

    total_records = len(records)
    devices_with_patch_override = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        overrides = rec.get("overrides") or []
        if not isinstance(overrides, list):
            continue
        device_id = rec.get("deviceId")
        matched = [
            o for o in overrides
            if isinstance(o, str) and any(kw.lower() in o.lower() for kw in PATCH_KEYWORDS)
        ]
        if matched:
            devices_with_patch_override.append({"deviceId": device_id, "overrides": matched})

    restricted = len(devices_with_patch_override) > 0

    input_summary = {
        "totalOverrideRecords": total_records,
        "devicesWithPatchOverride": len(devices_with_patch_override),
    }

    if restricted:
        sample = devices_with_patch_override[0]
        pass_reasons = [
            (
                "Found %d device-level policy override record(s) affecting patch management "
                "(e.g. deviceId=%s overrides=%s). This indicates patch auto-approval is scoped/"
                "restricted at the device level rather than applied as a blanket auto-approve "
                "across the whole fleet."
            ) % (len(devices_with_patch_override), sample.get("deviceId"), sample.get("overrides"))
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            (
                "No device-level policy override records referencing patch management were found "
                "among the %d override record(s) returned by getPolicyOverridesSummary. Without a "
                "documented per-device or per-category restriction, the patching policy's approval "
                "section cannot be confirmed as restricted from blanket auto-approval."
            ) % total_records
        ]
        recommendations = [
            "Review the patching policy approval section and configure category-level or device-"
            "scoped approval overrides instead of a single blanket auto-approve-all rule."
        ]

    result = {
        "isPatchAutoApprovalRestricted": restricted,
        "totalOverrideRecords": total_records,
        "devicesWithPatchOverride": len(devices_with_patch_override),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPatchAutoApprovalRestricted",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
