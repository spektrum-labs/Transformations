
import json
from datetime import datetime


def extract_input(input_data):
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
        total_results = len(domains)
    elif isinstance(data, dict):
        domains = data.get("domains") or []
        total_results = data.get("total_results") or len(domains)
    else:
        domains = []
        total_results = 0

    total_domains = len(domains)
    active_domains = [d for d in domains if isinstance(d, dict) and d.get("active")]
    scanned_domains = [d for d in domains if isinstance(d, dict) and d.get("scanned_at")]

    active_count = len(active_domains)
    scanned_count = len(scanned_domains)

    is_asm_enabled = total_domains > 0 and active_count > 0 and scanned_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_asm_enabled:
        sample_hosts = [d.get("hostname") for d in scanned_domains[:3] if isinstance(d, dict)]
        pass_reasons.append(
            "UpGuard /domains returned %d monitored domains (total_results=%d), of which %d are active and %d carry a scanned_at timestamp (e.g. %s), demonstrating active external attack surface monitoring."
            % (total_domains, total_results, active_count, scanned_count, ", ".join(sample_hosts))
        )
    else:
        if total_domains == 0:
            fail_reasons.append("The /domains endpoint returned zero monitored domains for this account.")
            recommendations.append("Add and verify at least one domain in UpGuard Breach Risk to enable attack surface monitoring.")
        elif active_count == 0:
            fail_reasons.append("None of the %d domains returned are marked active=true." % total_domains)
            recommendations.append("Activate monitoring on the organization's primary domains in UpGuard.")
        elif scanned_count == 0:
            fail_reasons.append("None of the %d domains returned carry a scanned_at timestamp, indicating no scans have run." % total_domains)
            recommendations.append("Confirm UpGuard's scanning schedule is running for the monitored domains.")

    result = {
        "isASMEnabled": is_asm_enabled,
        "totalDomains": total_domains,
        "activeDomains": active_count,
        "scannedDomains": scanned_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDomains": total_domains, "activeDomains": active_count, "scannedDomains": scanned_count},
        metadata={
            "transformationId": "isASMEnabled",
            "vendor": "UpGuard Threat Monitoring Data Leak Protection",
            "category": "asm",
        },
    )
