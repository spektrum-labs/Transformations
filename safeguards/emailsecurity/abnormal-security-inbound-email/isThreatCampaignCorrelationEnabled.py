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
        threat_id = None
        messages = []
    else:
        threat_id = data.get("threatId")
        messages = data.get("messages") or []
        if not isinstance(messages, list):
            messages = []

    message_count = len(messages)

    same_threat_ids = 0
    analysis_fields_present = 0
    for m in messages:
        if not isinstance(m, dict):
            continue
        if m.get("threatId") == threat_id and threat_id:
            same_threat_ids = same_threat_ids + 1
        if m.get("attackStrategy") or m.get("attackType") or m.get("attackedParty"):
            analysis_fields_present = analysis_fields_present + 1

    has_grouping_structure = bool(threat_id) and isinstance(messages, list) and message_count >= 1
    grouped_correlation = same_threat_ids == message_count and message_count > 0 and analysis_fields_present > 0

    correlation_enabled = bool(has_grouping_structure and grouped_correlation)

    input_summary = {
        "threatId": threat_id,
        "messageCount": message_count,
        "messagesSharingThreatId": same_threat_ids,
        "messagesWithAnalysisFields": analysis_fields_present,
    }

    if correlation_enabled:
        pass_reasons = [
            f"Threat {threat_id} groups {message_count} message(s) under a single threatId, "
            f"with {same_threat_ids} of {message_count} messages sharing that threatId and "
            f"{analysis_fields_present} carrying attackStrategy/attackType/attackedParty analysis fields, "
            "evidencing case-level correlation of related malicious messages rather than isolated events."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Threat detail response for threatId={threat_id} did not demonstrate grouped correlation: "
            f"messageCount={message_count}, messagesSharingThreatId={same_threat_ids}, "
            f"messagesWithAnalysisFields={analysis_fields_present}."
        ]
        recommendations = [
            "Verify Abnormal's threat-campaign correlation feature is enabled for this tenant so that "
            "related malicious messages are grouped into a single Case/threat object with analysis metadata."
        ]

    result = {
        "isThreatCampaignCorrelationEnabled": correlation_enabled,
        "messageCount": message_count,
        "messagesSharingThreatId": same_threat_ids,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isThreatCampaignCorrelationEnabled",
            "vendor": "Abnormal Security Inbound Email",
            "category": "emailsecurity",
        },
    )
