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


SHADOW_KEYWORDS = ["shadow", "unsanctioned", "unclaimed", "unmanaged", "rogue", "unauthorized", "unauthorised"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        folders = data
    elif isinstance(data, dict):
        folders = data.get("data") or data.get("apiResponse") or []
        if not isinstance(folders, list):
            folders = []
    else:
        folders = []

    matching_folders = []
    for f in folders:
        if not isinstance(f, dict):
            continue
        name = (f.get("name") or "").lower()
        desc = (f.get("description") or "").lower()
        filters = f.get("filters") or []
        filter_text = ""
        if isinstance(filters, list):
            filter_text = json.dumps(filters).lower()
        combined = name + " " + desc + " " + filter_text
        for kw in SHADOW_KEYWORDS:
            if kw in combined:
                matching_folders.append({
                    "id": f.get("id"),
                    "name": f.get("name"),
                    "description": f.get("description"),
                    "assetCount": f.get("current_asset_count"),
                })
                break

    total_folders = len(folders)
    is_enabled = len(matching_folders) > 0

    if is_enabled:
        names = ", ".join([str(m.get("name")) for m in matching_folders])
        pass_reasons = [
            f"Found {len(matching_folders)} of {total_folders} smart folder(s) named/described with shadow-IT related keywords: {names}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        sample_names = ", ".join([str(f.get("name")) for f in folders if isinstance(f, dict)][:5])
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_folders} smart folder(s) returned by getSmartFoldersList reference shadow IT, unsanctioned, unclaimed, or unmanaged assets. Folder name(s) observed: {sample_names}."
        ]
        recommendations = [
            "Create a dedicated Smart Folder (e.g. filtering on bd.addedtoportfolio or ownership/source columns) explicitly tagging shadow IT / unsanctioned / business-unit-provisioned assets so they are distinguishable in the inventory."
        ]

    result = {
        "isShadowITAssetTaggingEnabled": is_enabled,
        "totalSmartFolders": total_folders,
        "matchingSmartFolders": len(matching_folders),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalSmartFolders": total_folders, "matchingSmartFolders": len(matching_folders)},
        metadata={
            "transformationId": "isShadowITAssetTaggingEnabled",
            "vendor": "Tenable",
            "category": "asm",
        },
    )
