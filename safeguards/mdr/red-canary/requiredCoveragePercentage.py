"""
Transformation: requiredCoveragePercentage
Red Canary MDR - Endpoint Coverage Percentage

Computes the percentage of the expected device fleet that is enrolled
under Red Canary MDR monitoring. The enrolled count (numerator) comes from
meta.total_items, a fleet-wide aggregate returned by the getEndpoints API.
The expected device count (denominator) comes from the per-tenant safeguard
config injected into the input envelope. Both values are fleet-scoped.
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

    # Extract enrolled endpoint count from meta.total_items (fleet-wide aggregate).
    # With pagination follow=true, the runtime fetches all pages; meta.total_items
    # reflects the full enrolled fleet, not a single-page sample.
    meta = data.get("meta") or {}
    total_items = meta.get("total_items")
    items = data.get("data") or []
    if total_items is not None and isinstance(total_items, int) and total_items >= 0:
        enrolled_count = total_items
    else:
        enrolled_count = len(items)

    # Extract expected device count from per-tenant safeguard config.
    # The config is injected at the top level of the input envelope (before
    # extract_input unwraps it), so we read from the raw input dict.
    raw_input = input if isinstance(input, dict) else {}
    config = raw_input.get("config") or raw_input.get("settings") or raw_input.get("safeguard_config") or {}
    if not isinstance(config, dict):
        config = {}

    raw_expected = (
        config.get("expectedDeviceCount") or
        config.get("expectedEndpoints") or
        config.get("expected_device_count") or
        config.get("expected_endpoints") or
        config.get("expectedDevices") or
        0
    )
    expected_devices = int(raw_expected) if raw_expected else 0

    # Compute coverage percentage using same-scope values:
    # enrolled_count  = fleet-wide MDR-enrolled endpoints (from meta.total_items)
    # expected_devices = fleet-wide expected endpoints (from safeguard config)
    no_config = expected_devices <= 0
    if no_config:
        # No expected count configured; report enrolled count relative to itself
        # (100% by definition). Flag this as a finding so operators know to
        # configure the expected device count for accurate threshold evaluation.
        coverage_pct = 100.0 if enrolled_count > 0 else 0.0
        effective_denominator = enrolled_count
    else:
        raw_pct = (enrolled_count / expected_devices) * 100.0
        coverage_pct = round(min(raw_pct, 100.0), 2)
        effective_denominator = expected_devices

    threshold = 95.0
    passes = coverage_pct >= threshold

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if no_config:
        additional_findings.append(
            "No expectedDeviceCount found in safeguard config; coverage denominator defaulted to "
            "the enrolled count (%d). Configure expectedDeviceCount in the safeguard settings "
            "for accurate threshold evaluation against the actual device fleet." % enrolled_count
        )

    if passes:
        pass_reasons.append(
            "%d endpoints are enrolled in Red Canary MDR out of %d expected devices, "
            "yielding %.2f%% coverage which meets the %.0f%% threshold. "
            "(source: meta.total_items=%s)" % (
                enrolled_count,
                effective_denominator,
                coverage_pct,
                threshold,
                str(total_items),
            )
        )
    else:
        gap = effective_denominator - enrolled_count
        fail_reasons.append(
            "Only %d endpoints are enrolled in Red Canary MDR out of %d expected devices, "
            "yielding %.2f%% coverage which is below the %.0f%% required threshold. "
            "%d endpoints are not yet covered." % (
                enrolled_count,
                effective_denominator,
                coverage_pct,
                threshold,
                gap,
            )
        )
        recommendations.append(
            "Enroll the remaining %d endpoints in Red Canary MDR to reach the %.0f%% "
            "coverage threshold. Review unmonitored hosts in the asset inventory and "
            "deploy the Red Canary sensor to bring coverage to the required level." % (
                gap,
                threshold,
            )
        )

    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "enrolledEndpoints": enrolled_count,
            "expectedDevices": effective_denominator,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "metaTotalItems": total_items,
            "dataArrayLength": len(items),
            "enrolledCount": enrolled_count,
            "expectedDevices": effective_denominator,
            "configPresent": not no_config,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
