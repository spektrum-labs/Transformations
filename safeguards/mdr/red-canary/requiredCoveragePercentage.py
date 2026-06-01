"""
Transformation: requiredCoveragePercentage
Red Canary MDR — validates that the percentage of endpoints enrolled in Red Canary MDR
meets the Cyvatar baseline coverage threshold (default >=95% of expected device fleet).

Numerator:   meta.total_items from getEndpoints (all pages aggregated via follow=true)
Denominator: expected fleet size from per-tenant safeguard config
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
        for attempt in range(3):
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

    if isinstance(data, list):
        endpoints_list = data
        meta = {}
        total_items_raw = len(endpoints_list)
        config_lookup = {}
    elif isinstance(data, dict):
        endpoints_list = data.get("data") or []
        meta = data.get("meta") or {}
        total_items_raw = meta.get("total_items")
        config_lookup = data
    else:
        endpoints_list = []
        meta = {}
        total_items_raw = None
        config_lookup = {}

    if total_items_raw is None:
        enrolled_count = len(endpoints_list)
    else:
        enrolled_count = int(total_items_raw)

    expected_count = None
    config_key_candidates = [
        "expectedEndpoints",
        "expectedDeviceCount",
        "deviceCount",
        "expectedDevices",
        "totalExpectedEndpoints",
        "fleetSize",
    ]
    for ck in config_key_candidates:
        val = config_lookup.get(ck)
        if val is not None:
            try:
                expected_count = int(val)
            except (TypeError, ValueError):
                pass
            if expected_count is not None:
                break

    if expected_count is None or expected_count <= 0:
        # No config denominator available — treat enrolled fleet as 100% coverage
        expected_count = enrolled_count if enrolled_count > 0 else 0

    # --- Coverage percentage ---
    if expected_count == 0:
        coverage_pct = 0.0
    else:
        raw_pct = (float(enrolled_count) / float(expected_count)) * 100.0
        # Cap at 100 — more endpoints than expected is still 100% covered
        coverage_pct = raw_pct if raw_pct <= 100.0 else 100.0

    coverage_pct = round(coverage_pct, 2)

    # --- Evaluation reasons ---
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if coverage_pct >= 95.0:
        pass_reasons.append(
            f"{enrolled_count} of {expected_count} expected endpoints are enrolled in Red Canary MDR "
            f"(meta.total_items={enrolled_count}), yielding {coverage_pct}% coverage which meets the >=95% threshold."
        )
    else:
        gap = expected_count - enrolled_count
        fail_reasons.append(
            f"Only {enrolled_count} of {expected_count} expected endpoints are enrolled in Red Canary MDR "
            f"(meta.total_items={enrolled_count}), yielding {coverage_pct}% coverage which is below the >=95% threshold."
        )
        recommendations.append(
            f"Enroll the remaining {gap} endpoint(s) in Red Canary MDR to reach the 95% coverage baseline. "
            f"Verify that the Red Canary sensor is deployed and active on all devices in the expected fleet."
        )

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
        input_summary={
            "totalItems": total_items_raw,
            "enrolledEndpoints": enrolled_count,
            "expectedEndpoints": expected_count,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
