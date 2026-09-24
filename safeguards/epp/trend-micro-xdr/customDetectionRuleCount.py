
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
        models = data
    elif isinstance(data, dict):
        models = data.get("data") or []
        if not isinstance(models, list):
            models = []
    else:
        models = []

    total_models = len(models)
    enabled_models = [m for m in models if isinstance(m, dict) and m.get("enabled") is True]
    enabled_count = len(enabled_models)

    sample_names = [m.get("name") for m in enabled_models[:5] if isinstance(m, dict)]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_models == 0:
        fail_reasons.append(
            "No detection models were returned by the Detection Models API (/v2.0/xdr/dmm/models); "
            "unable to determine any custom detection rule count."
        )
        recommendations.append(
            "Verify the API credential has access to the Detection Models list endpoint and that "
            "detection models are configured for this tenant."
        )
    else:
        pass_reasons.append(
            f"Detection Models API returned {total_models} total models, of which {enabled_count} "
            f"have enabled=true (e.g. {', '.join([n for n in sample_names if n]) or 'none'})."
        )

    result = {
        "customDetectionRuleCount": enabled_count,
        "totalDetectionModels": total_models,
    }

    input_summary = {
        "totalDetectionModels": total_models,
        "enabledDetectionModels": enabled_count,
    }

    metadata = {
        "transformationId": "customDetectionRuleCount",
        "vendor": "Trend Micro XDR",
        "category": "epp",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
