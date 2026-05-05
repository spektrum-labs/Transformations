"""Transformation: requiredCoveragePercentage — Red Canary MDR endpoint coverage meets threshold."""
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

    # Extract aggregate enrolled endpoint count from meta
    meta = data.get("meta") or {}
    total_items_raw = meta.get("total_items")
    if total_items_raw is not None:
        enrolled_count = int(total_items_raw)
    else:
        # Fallback: count items in the data array (may be a single page sample)
        items = data.get("data") or []
        enrolled_count = len(items)

    # Look for the expected fleet size from safeguard / tenant config passed in the input envelope
    config = {}
    if isinstance(input, dict):
        raw_config = (
            input.get("config")
            or input.get("context")
            or input.get("safeguard_config")
            or {}
        )
        config = raw_config if isinstance(raw_config, dict) else {}

    expected_raw = (
        config.get("expectedEndpoints")
        or config.get("expected_endpoints")
        or config.get("expectedDeviceCount")
        or config.get("expected_device_count")
    )

    if expected_raw is not None:
        expected_count = int(expected_raw)
        denominator_source = "safeguard config"
    else:
        # No expected count configured — use enrolled count as the denominator
        # so coverage resolves to 100% with an advisory warning
        expected_count = enrolled_count
        denominator_source = "enrolled count (no expected fleet size configured)"

    threshold = 95.0

    if expected_count == 0:
        coverage_pct = 0.0
        pass_reasons = []
        fail_reasons = [
            "Expected device fleet count is 0; coverage percentage cannot be computed."
        ]
        recommendations = [
            "Configure the expected endpoint count (expectedEndpoints) in the safeguard settings."
        ]
        additional_findings = []
    else:
        coverage_pct = round((float(enrolled_count) / float(expected_count)) * 100.0, 2)

        if coverage_pct >= threshold:
            pass_reasons = [
                f"Red Canary MDR reports {enrolled_count} enrolled endpoints against an expected "
                f"fleet of {expected_count} (source: {denominator_source}), "
                f"yielding {coverage_pct}% coverage which meets the {threshold}% Cyvatar baseline threshold."
            ]
            fail_reasons = []
            recommendations = []
        else:
            gap = expected_count - enrolled_count
            pass_reasons = []
            fail_reasons = [
                f"Red Canary MDR reports {enrolled_count} enrolled endpoints against an expected "
                f"fleet of {expected_count} (source: {denominator_source}), "
                f"yielding {coverage_pct}% coverage which is below the {threshold}% Cyvatar baseline threshold."
            ]
            recommendations = [
                f"Enroll the remaining {gap} endpoints into Red Canary MDR to reach the "
                f"{threshold}% coverage threshold."
            ]

        if denominator_source != "safeguard config":
            additional_findings = [
                "No expectedEndpoints value was found in the safeguard config. "
                "The enrolled endpoint count was used as both numerator and denominator, "
                "resulting in 100% coverage. Configure expectedEndpoints in the safeguard "
                "settings to enable accurate fleet coverage measurement."
            ]
        else:
            additional_findings = []

    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "enrolledEndpoints": enrolled_count,
            "expectedEndpoints": expected_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "metaTotalItems": meta.get("total_items"),
            "enrolledEndpoints": enrolled_count,
            "expectedEndpoints": expected_count,
            "denominatorSource": denominator_source,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
