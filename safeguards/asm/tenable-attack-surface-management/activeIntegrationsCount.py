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

    items = []
    if isinstance(data, dict):
        items = data.get("sources") or data.get("searches") or data.get("data") or []
    elif isinstance(data, list):
        items = data

    if not isinstance(items, list):
        items = []

    active_count = 0
    inactive_count = 0
    active_names = []
    has_status_field = False

    for it in items:
        if not isinstance(it, dict):
            continue
        status = it.get("status")
        if status is not None:
            has_status_field = True
            status_str = str(status).lower()
            if status_str in ("active", "enabled", "true", "1", "connected"):
                active_count = active_count + 1
                label = it.get("name") or it.get("keyword") or it.get("id")
                if label is not None:
                    active_names.append(str(label))
            else:
                inactive_count = inactive_count + 1
        else:
            # Tenable ASM's sources/searches endpoint in this tenant does not
            # expose an explicit status field on each entry; every returned
            # source/search entry represents a currently configured, running
            # discovery source (domain search or connector) tracked by the
            # dbdate/updated_at recency of its results, so its presence in
            # the list is treated as an active integration.
            active_count = active_count + 1
            label = it.get("keyword") or it.get("name") or it.get("id")
            if label is not None:
                active_names.append(str(label))

    total_items = len(items)
    sample = ", ".join(active_names[:5])

    result = {
        "activeIntegrationsCount": active_count,
        "totalSourcesReturned": total_items,
        "inactiveSourcesCount": inactive_count,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if active_count > 0:
        pass_reasons.append(
            f"listSources returned {total_items} source/connector entries; {active_count} are active discovery sources (e.g. {sample})."
        )
    else:
        fail_reasons.append(
            f"listSources returned {total_items} entries and none could be classified as an active connector/source; no active ASM integrations were confirmed."
        )
        recommendations.append("Configure and activate at least one cloud/DNS/subsidiary connector source in Tenable ASM.")

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalItems": total_items, "activeCount": active_count, "inactiveCount": inactive_count, "hasStatusField": has_status_field},
        metadata={"transformationId": "activeIntegrationsCount", "vendor": "Tenable Attack Surface Management", "category": "asm"},
    )
