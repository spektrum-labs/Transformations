import json
from datetime import datetime, timedelta


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


def parse_iso_date(s):
    try:
        if not s or not isinstance(s, str):
            return None
        date_part = s
        if "T" in s:
            date_part, time_part = s.split("T", 1)
        else:
            time_part = "00:00:00"
        parts = date_part.split("-")
        if len(parts) != 3:
            return None
        y, m, d = int(parts[0]), int(parts[1]), int(parts[2])
        time_part = time_part.rstrip("Z")
        hms = time_part.split(".")[0]
        hms_parts = hms.split(":")
        hh = int(hms_parts[0]) if len(hms_parts) > 0 and hms_parts[0] != "" else 0
        mm = int(hms_parts[1]) if len(hms_parts) > 1 else 0
        ss = int(hms_parts[2]) if len(hms_parts) > 2 else 0
        return datetime(y, m, d, hh, mm, ss)
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        assets = data
    elif isinstance(data, dict):
        assets = data.get("assets") or data.get("data") or []
        if not isinstance(assets, list):
            assets = []
    else:
        assets = []

    now = datetime.utcnow()
    threshold = now + timedelta(days=30)

    total_assets = len(assets)
    assets_with_cert = 0
    expiring_soon = 0
    already_expired = 0
    parse_failures = 0
    expiring_hostnames = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        valid_to = asset.get("ssl.valid_to")
        if not valid_to:
            continue
        assets_with_cert = assets_with_cert + 1
        parsed = parse_iso_date(valid_to)
        if parsed is None:
            parse_failures = parse_failures + 1
            continue
        if parsed < now:
            already_expired = already_expired + 1
        elif parsed <= threshold:
            expiring_soon = expiring_soon + 1
            if len(expiring_hostnames) < 10:
                hostname = asset.get("bd.hostname") or asset.get("id") or "unknown"
                expiring_hostnames.append(hostname)

    if expiring_soon > 0:
        sample = ", ".join([str(h) for h in expiring_hostnames])
        pass_reasons = [
            f"{expiring_soon} of {assets_with_cert} internet-facing assets with an ssl.valid_to value expire within the next 30 days (threshold {threshold.isoformat()}Z). Examples: {sample}."
        ]
        fail_reasons = []
        recommendations = [
            "Renew TLS certificates for the assets expiring within 30 days before they lapse and cause outages or trust warnings."
        ]
    else:
        pass_reasons = []
        fail_reasons = [
            f"No internet-facing assets (out of {assets_with_cert} with a certificate expiry date, {total_assets} total assets) have a TLS certificate expiring within the next 30 days."
        ]
        recommendations = []

    result = {
        "certificateExpiringSoonCount": expiring_soon,
        "totalAssets": total_assets,
        "assetsWithCertificateData": assets_with_cert,
        "alreadyExpiredCount": already_expired,
        "certParseFailures": parse_failures,
    }

    input_summary = {
        "totalAssets": total_assets,
        "assetsWithCertificateData": assets_with_cert,
        "expiringSoonCount": expiring_soon,
        "alreadyExpiredCount": already_expired,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "certificateExpiringSoonCount",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
