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


SATURATION_THRESHOLD = 90


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    perf_score = data.get("perfScore")

    transformation_errors = []
    if perf_score is None:
        transformation_errors.append("perfScore field missing from getDeviceAppliancePerformance response")
        perf_score_value = None
    else:
        try:
            perf_score_value = float(perf_score)
        except (TypeError, ValueError):
            transformation_errors.append(f"perfScore value '{perf_score}' is not numeric")
            perf_score_value = None

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if perf_score_value is None:
        is_performant = False
        fail_reasons.append(
            "No usable perfScore was returned by getDeviceAppliancePerformance, so uplink health cannot be confirmed."
        )
        recommendations.append(
            "Verify the MX appliance serial is correct and that the device is reporting performance telemetry to the dashboard."
        )
    else:
        is_performant = perf_score_value < SATURATION_THRESHOLD
        if is_performant:
            pass_reasons.append(
                f"Device perfScore is {perf_score_value}, below the {SATURATION_THRESHOLD} saturation threshold, indicating WAN uplinks are not overloaded."
            )
        else:
            fail_reasons.append(
                f"Device perfScore is {perf_score_value}, at or above the {SATURATION_THRESHOLD} saturation threshold, indicating the MX appliance's WAN uplinks/throughput capacity are near or at saturation."
            )
            recommendations.append(
                "Investigate WAN uplink utilization (bandwidth, loss, latency) on this MX appliance and consider upgrading uplink capacity or offloading traffic to reduce inline inspection degradation."
            )

    result = {
        "isFirewallPerformant": is_performant,
        "perfScore": perf_score_value,
    }

    input_summary = {"perfScore": perf_score_value}

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isFirewallPerformant",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
        transformation_errors=transformation_errors,
    )
