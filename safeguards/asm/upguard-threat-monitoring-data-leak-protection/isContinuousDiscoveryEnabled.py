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
        domains = data
    elif isinstance(data, dict):
        domains = data.get("domains") or data.get("data") or []
        if not isinstance(domains, list):
            domains = []
    else:
        domains = []

    total_domains = len(domains)

    scan_dates = []
    domains_with_scan = 0
    for d in domains:
        if not isinstance(d, dict):
            continue
        scanned_at = d.get("scanned_at")
        if scanned_at and isinstance(scanned_at, str):
            domains_with_scan = domains_with_scan + 1
            date_part = scanned_at.split("T")[0]
            if date_part not in scan_dates:
                scan_dates.append(date_part)

    distinct_scan_dates = len(scan_dates)

    # Continuous discovery is evidenced by domains actually carrying scan
    # timestamps that span more than one calendar date -- a single-day
    # snapshot (or none at all) does not demonstrate ongoing re-scanning.
    is_enabled = domains_with_scan > 0 and distinct_scan_dates >= 2

    result = {
        "isContinuousDiscoveryEnabled": is_enabled,
        "totalDomains": total_domains,
        "domainsWithScanTimestamp": domains_with_scan,
        "distinctScanDates": distinct_scan_dates,
    }

    input_summary = {
        "totalDomains": total_domains,
        "domainsWithScanTimestamp": domains_with_scan,
        "distinctScanDates": distinct_scan_dates,
    }

    metadata = {
        "transformationId": "isContinuousDiscoveryEnabled",
        "vendor": "UpGuard Threat Monitoring Data Leak Protection",
        "category": "asm",
    }

    if total_domains == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No domains were returned by getDomains, so there is no evidence of ongoing automated scanning."],
            recommendations=["Enable domain monitoring in UpGuard so hostnames belonging to the organization are tracked and scanned."],
            input_summary=input_summary,
            metadata=metadata,
        )

    if is_enabled:
        pass_reasons = [
            f"Of {total_domains} monitored domains, {domains_with_scan} carry a scanned_at timestamp spanning {distinct_scan_dates} distinct calendar dates, indicating UpGuard is re-scanning the domain fleet on an ongoing basis rather than only at initial onboarding."
        ]
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata=metadata,
        )
    else:
        fail_reasons = [
            f"Of {total_domains} monitored domains, only {domains_with_scan} carry a scanned_at timestamp, spanning {distinct_scan_dates} distinct calendar date(s), which does not demonstrate ongoing/continuous re-scanning across multiple days."
        ]
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=["Confirm automated domain discovery and daily re-scanning is enabled in UpGuard BreachSight for this tenant."],
            input_summary=input_summary,
            metadata=metadata,
        )
