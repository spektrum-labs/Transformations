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

    threats = []
    total = 0

    if isinstance(data, dict):
        raw_threats = data.get("threats")
        threats = raw_threats if isinstance(raw_threats, list) else []
        total_val = data.get("total")
        total = total_val if isinstance(total_val, int) else len(threats)
    elif isinstance(data, list):
        threats = data
        total = len(threats)

    threat_ids = [t.get("threatId") for t in threats if isinstance(t, dict) and t.get("threatId")]
    distinct_ids_sample = len(set(threat_ids))

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    is_enabled = False

    if total > 0 and len(threat_ids) > 0:
        is_enabled = True
        pass_reasons.append(
            f"getThreats returned total={total} threats, each identified by a distinct threatId "
            f"(sampled {distinct_ids_sample} unique threatId values in this page). Per Abnormal's "
            "documented model, each threatId represents a threat campaign that correlates multiple "
            "related messages and identity signals into a single grouped entity, evidencing that "
            "threat-campaign correlation is active for this tenant."
        )
    else:
        fail_reasons.append(
            f"getThreats returned total={total} threats with {len(threat_ids)} threatId values present "
            "in the sampled page, so no evidence of campaign-grouped threatId entities could be observed."
        )
        recommendations.append(
            "Confirm the tenant has active threat detections and that the /v1/threats endpoint is "
            "returning populated threatId-grouped records; if the feed is empty, campaign correlation "
            "cannot be verified from this endpoint."
        )

    result = {
        "isThreatCampaignCorrelationEnabled": is_enabled,
        "totalThreats": total,
        "sampledThreatIdCount": len(threat_ids),
    }

    input_summary = {
        "totalThreats": total,
        "sampledThreatIdCount": len(threat_ids),
        "distinctSampledThreatIds": distinct_ids_sample,
    }

    metadata = {
        "transformationId": "isThreatCampaignCorrelationEnabled",
        "vendor": "Abnormal Security",
        "category": "emailsecurity",
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
