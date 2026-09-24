"""Transformation: isThreatIntelIOCLookupEnabled

Uses the Trend Micro XDR Detection Models list (/v2.0/xdr/dmm/models) to
determine whether the tenant's Threat Intelligence detection model (used
to power IOC hash/domain/IP lookups via Threat Intelligence Search) is
enabled.
"""

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
        models = data.get("data") or data.get("items") or []
        if not isinstance(models, list):
            models = []
    else:
        models = []

    total_models = len(models)

    ti_models = []
    for m in models:
        if not isinstance(m, dict):
            continue
        name = m.get("name") or ""
        if "threat intelligence" in name.lower():
            ti_models.append(m)

    ti_enabled = False
    matched_ids = []
    for m in ti_models:
        matched_ids.append(m.get("modelId") or "unknown")
        if m.get("enabled") is True:
            ti_enabled = True

    input_summary = {
        "totalModelsEvaluated": total_models,
        "threatIntelModelsFound": len(ti_models),
        "threatIntelModelIds": matched_ids,
    }

    if ti_models and ti_enabled:
        pass_reasons = [
            f"Threat Intelligence detection model(s) {matched_ids} found with enabled=true "
            f"out of {total_models} detection models scanned, confirming IOC (hash/domain/IP) "
            f"lookup via Threat Intelligence Search is active."
        ]
        fail_reasons = []
        recommendations = []
        result_value = True
    elif ti_models and not ti_enabled:
        pass_reasons = []
        fail_reasons = [
            f"Threat Intelligence detection model(s) {matched_ids} were found among "
            f"{total_models} detection models but all report enabled=false."
        ]
        recommendations = [
            "Enable the Threat Intelligence detection model in Trend Vision One "
            "Detection Model Management to activate IOC lookup via Threat Intelligence Search."
        ]
        result_value = False
    else:
        pass_reasons = []
        fail_reasons = [
            f"No detection model named 'Threat Intelligence' was found among the "
            f"{total_models} detection models returned by /v2.0/xdr/dmm/models."
        ]
        recommendations = [
            "Verify that the Threat Intelligence detection model is provisioned for this "
            "tenant and enabled in Detection Model Management."
        ]
        result_value = False

    return create_response(
        result={
            "isThreatIntelIOCLookupEnabled": result_value,
            "threatIntelModelsFound": len(ti_models),
            "totalModelsEvaluated": total_models,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isThreatIntelIOCLookupEnabled",
            "vendor": "Trend Micro XDR",
            "category": "epp",
        },
    )
