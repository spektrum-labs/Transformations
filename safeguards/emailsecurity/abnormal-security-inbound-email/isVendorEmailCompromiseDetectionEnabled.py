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

    if isinstance(data, list):
        vendors = data
    elif isinstance(data, dict):
        vendors = data.get("vendors") or data.get("data") or []
        if not isinstance(vendors, list):
            vendors = []
    else:
        vendors = []

    tracked_domains = []
    for v in vendors:
        if isinstance(v, dict):
            domain = v.get("vendorDomain")
            if domain:
                tracked_domains.append(domain)

    vendor_count = len(tracked_domains)
    is_enabled = vendor_count > 0

    input_summary = {
        "vendorCount": vendor_count,
        "sampleVendorDomains": tracked_domains[:5],
    }

    if is_enabled:
        pass_reasons = [
            f"VendorBase /v1/vendors endpoint returned {vendor_count} tracked vendor domains "
            f"(e.g. {', '.join(tracked_domains[:5])}), indicating Vendor Email Compromise (VEC) "
            f"monitoring is licensed and actively tracking third-party vendor domains for this tenant."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "The /v1/vendors endpoint returned zero tracked vendor domains, indicating the "
            "VendorBase / Vendor Email Compromise (VEC) monitoring product is not populated or "
            "not licensed for this tenant."
        ]
        recommendations = [
            "Enable and license the Abnormal Security VendorBase / Vendor Email Compromise "
            "detection product for this tenant so vendor domains are tracked and monitored."
        ]

    return create_response(
        result={
            "isVendorEmailCompromiseDetectionEnabled": is_enabled,
            "trackedVendorCount": vendor_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isVendorEmailCompromiseDetectionEnabled",
            "vendor": "Abnormal Security Inbound Email",
            "category": "emailsecurity",
        },
    )
