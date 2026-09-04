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


ATO_EVENT_TYPES = [
    "account_takeover",
    "accounttakeover",
    "anomalous_login",
    "anomaly",
    "impossible_travel",
    "suspicious_login",
    "brute_force",
    "login_anomaly",
    "ato",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    is_error = bool(data.get("error")) or data.get("statusCode") == 401 or data.get("status") == "Error"

    if is_error:
        api_message = data.get("message") or data.get("errorMessage") or "unknown API error"
        result = {
            "isAccountTakeoverDetectionEnabled": False,
            "atoEventCount": 0,
            "totalEventsReturned": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                f"queryEvents returned an authentication/API error ('{api_message}', statusCode={data.get('statusCode')}); unable to retrieve events to confirm account takeover detection is active."
            ],
            recommendations=[
                "Verify clientId/accessKey credentials configured for this integration and confirm the API user has permission to query security events via /app/hec-api/v1.0/event/query."
            ],
            input_summary={"error": True, "statusCode": data.get("statusCode")},
            api_errors=[api_message],
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    matching = []
    for e in events:
        if isinstance(e, dict):
            etype = (e.get("type") or "")
            etype = etype.lower() if isinstance(etype, str) else ""
            if etype in ATO_EVENT_TYPES:
                matching.append(e)

    count = len(matching)
    total_events = len(events)
    enabled = count > 0

    input_summary = {
        "totalEventsReturned": total_events,
        "atoMatchingEventCount": count,
    }

    if enabled:
        sample_ids = [str(e.get("eventId")) for e in matching[:3] if isinstance(e, dict)]
        pass_reasons = [
            f"queryEvents returned {count} of {total_events} events with account-takeover/anomaly type "
            f"(e.g. eventIds {sample_ids}), confirming account takeover detection is active and generating events."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"queryEvents returned {total_events} events but none matched account-takeover/anomaly event types "
            f"({ATO_EVENT_TYPES}); no evidence that account takeover detection produced any findings for this tenant."
        ]
        recommendations = [
            "Confirm the Anomaly Detection / Account Takeover protection capability is enabled on the Microsoft 365 "
            "or Google Workspace SaaS connector in the Harmony Email and Collaboration admin console, and re-run the "
            "query with a broader date range or eventTypes filter including account-takeover categories."
        ]

    result = {
        "isAccountTakeoverDetectionEnabled": enabled,
        "atoEventCount": count,
        "totalEventsReturned": total_events,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
    )
