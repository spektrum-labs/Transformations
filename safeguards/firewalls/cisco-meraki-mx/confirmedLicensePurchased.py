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

    status = data.get("status") or ""
    expiration_date = data.get("expirationDate") or ""
    licensed_counts = data.get("licensedDeviceCounts") or {}
    licensed_counts = licensed_counts if isinstance(licensed_counts, dict) else {}

    mx_license_keys = [k for k in licensed_counts.keys() if "MX" in k.upper()]
    mx_license_total = 0
    for k in mx_license_keys:
        v = licensed_counts.get(k)
        if isinstance(v, (int, float)):
            mx_license_total = mx_license_total + v

    status_ok = status.strip().upper() == "OK"
    has_mx_license = mx_license_total > 0

    confirmed = status_ok and has_mx_license

    input_summary = {
        "status": status,
        "expirationDate": expiration_date,
        "mxLicenseKeys": mx_license_keys,
        "mxLicenseTotal": mx_license_total,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        pass_reasons.append(
            f"Organization license overview status is '{status}' and licensedDeviceCounts includes MX license entries {mx_license_keys} totaling {mx_license_total} seats, expiring {expiration_date}."
        )
    else:
        if not status_ok:
            fail_reasons.append(
                f"Organization license overview status is '{status}' (expected 'OK'), indicating a trial, expired, or unlicensed state."
            )
            recommendations.append(
                "Purchase or renew a valid Meraki license for the organization so the licenses/overview status reports 'OK'."
            )
        if not has_mx_license:
            fail_reasons.append(
                f"licensedDeviceCounts {licensed_counts} contains no MX-prefixed license entries, so no MX firewall license is confirmed purchased."
            )
            recommendations.append(
                "Purchase an MX appliance license (e.g. MX enterprise/advanced security license) and assign it in the Meraki dashboard."
            )

    result = {
        "confirmedLicensePurchased": confirmed,
        "licenseStatus": status,
        "mxLicenseCount": mx_license_total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
