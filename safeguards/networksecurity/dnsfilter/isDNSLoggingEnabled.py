"""
Transformation: isDNSLoggingEnabled
Criterion: DNS-2.4 [Recommended]: DNS Query Logging Enabled
Vendor: DNSFilter
Category: Network Security
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

    org_data = data.get("data") or {}
    org_data = org_data if isinstance(org_data, dict) else {}
    attributes = org_data.get("attributes") or {}
    attributes = attributes if isinstance(attributes, dict) else {}

    org_name = attributes.get("name") or "Unknown"
    privacy_mode = attributes.get("privacy_mode") or ""
    msp_privacy_mode = attributes.get("msp_privacy_mode") or ""

    # Determine effective privacy mode.
    # "inherit" means the org defers to the MSP-level setting.
    # "standard" means full DNS query logging is active.
    # Other modes ("private", "anonymized", etc.) restrict log visibility.
    if privacy_mode == "inherit":
        effective_mode = msp_privacy_mode if msp_privacy_mode else "unknown"
        mode_source = "msp_privacy_mode (inherited from MSP)"
    else:
        effective_mode = privacy_mode if privacy_mode else "unknown"
        mode_source = "privacy_mode"

    logging_enabled = effective_mode == "standard"

    input_summary = {
        "organizationName": org_name,
        "privacyMode": privacy_mode,
        "mspPrivacyMode": msp_privacy_mode,
        "effectiveMode": effective_mode,
        "modeSource": mode_source,
    }

    if logging_enabled:
        pass_reasons = [
            f"DNS query logging is enabled for organization '{org_name}'. "
            f"The effective privacy mode is 'standard' (sourced from {mode_source}), "
            f"indicating full DNS query logging is active and available for audit and threat analysis."
        ]
        if privacy_mode == "inherit":
            pass_reasons.append(
                f"Organization privacy_mode is 'inherit'; the MSP-level msp_privacy_mode is "
                f"'standard', so full logging applies to this organization."
            )
        fail_reasons = []
        recommendations = []
    else:
        fail_reasons = [
            f"DNS query logging is not fully enabled for organization '{org_name}'. "
            f"The effective privacy mode is '{effective_mode}' (sourced from {mode_source}), "
            f"which restricts DNS query log data visibility."
        ]
        pass_reasons = []
        recommendations = [
            f"Set the organization's privacy_mode (or the MSP-level msp_privacy_mode if using "
            f"'inherit') to 'standard' to enable full DNS query logging for audit and threat analysis."
        ]

    return create_response(
        result={
            "isDNSLoggingEnabled": logging_enabled,
            "organizationName": org_name,
            "privacyMode": privacy_mode,
            "mspPrivacyMode": msp_privacy_mode,
            "effectivePrivacyMode": effective_mode,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isDNSLoggingEnabled",
            "vendor": "DNSFilter",
            "category": "networksecurity",
        },
    )
