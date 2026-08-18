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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 401:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    envelope = data.get("responseEnvelope") or {}
    total_records = envelope.get("totalRecordsNumber")
    if not isinstance(total_records, int):
        total_records = len(events)

    correlated_count = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        indicator = ev.get("confidenceIndicator")
        severity = ev.get("severity")
        if indicator not in (None, "") or severity not in (None, ""):
            correlated_count = correlated_count + 1

    sample_size = len(events)

    if sample_size == 0:
        result = {
            "isGlobalIntelligenceNetworkCorrelationEnabled": False,
            "sampledEvents": 0,
            "correlatedEvents": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No events were returned by the event query, so ThreatCloud correlation "
                          "coverage (confidenceIndicator/severity presence) could not be verified."],
            recommendations=["Confirm event history exists in the tenant and re-run the query "
                              "with a broader date range or valid authentication."],
            input_summary={"sampledEvents": 0, "totalRecords": total_records},
            api_errors=api_errors,
            metadata={"transformationId": "isGlobalIntelligenceNetworkCorrelationEnabled",
                      "vendor": "Check Point Software Technologies Email Security",
                      "category": "Email Security"},
        )

    all_correlated = correlated_count == sample_size

    result = {
        "isGlobalIntelligenceNetworkCorrelationEnabled": all_correlated,
        "sampledEvents": sample_size,
        "correlatedEvents": correlated_count,
        "totalRecords": total_records,
    }

    if all_correlated:
        pass_reasons = [
            f"All {sample_size} events returned by the event query carry a non-empty "
            f"confidenceIndicator and/or severity value ({correlated_count}/{sample_size}), "
            f"confirming each message was scored by Check Point's ThreatCloud global "
            f"intelligence correlation before a verdict was issued."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Only {correlated_count} of {sample_size} events returned by the event query "
            f"carry a populated confidenceIndicator/severity value, indicating some messages "
            f"were not correlated against ThreatCloud before a verdict was issued."
        ]
        recommendations = [
            "Investigate events missing confidenceIndicator/severity values to confirm "
            "ThreatCloud correlation is applied to every processed message."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"sampledEvents": sample_size, "correlatedEvents": correlated_count,
                        "totalRecords": total_records},
        api_errors=api_errors,
        metadata={"transformationId": "isGlobalIntelligenceNetworkCorrelationEnabled",
                  "vendor": "Check Point Software Technologies Email Security",
                  "category": "Email Security"},
    )
