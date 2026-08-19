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

    enabled = data.get("enabled")
    primary_serial = data.get("primarySerial")
    spare_serial = data.get("spareSerial")
    uplink_mode = data.get("uplinkMode")

    is_enabled = bool(enabled) and bool(spare_serial)

    input_summary = {
        "enabled": enabled,
        "primarySerial": primary_serial,
        "spareSerial": spare_serial,
        "uplinkMode": uplink_mode,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"Warm spare (HA) is enabled with enabled={enabled}, "
            f"primarySerial={primary_serial}, spareSerial={spare_serial}, uplinkMode={uplink_mode}."
        )
    else:
        if not enabled:
            fail_reasons.append(
                f"Warm spare 'enabled' field is {enabled}, indicating no HA failover is configured."
            )
        elif not spare_serial:
            fail_reasons.append(
                "Warm spare is marked enabled but no spareSerial is configured for a secondary appliance."
            )
        recommendations.append(
            "Configure a secondary MX appliance as a warm spare and enable HA (High Availability) failover "
            "in the network's appliance/warmSpare settings."
        )

    result = {
        "haModeEnabled": is_enabled,
        "primarySerial": primary_serial,
        "spareSerial": spare_serial,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "haModeEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
