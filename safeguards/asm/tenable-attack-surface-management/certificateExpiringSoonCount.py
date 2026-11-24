
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


def parse_iso_date(value):
    if not value or not isinstance(value, str):
        return None
    try:
        date_part = value.split("T")[0]
        parts = date_part.split("-")
        if len(parts) != 3:
            return None
        year = int(parts[0])
        month = int(parts[1])
        day = int(parts[2])
        return datetime(year, month, day)
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        assets = data
    elif isinstance(data, dict):
        assets = data.get("assets") or data.get("data") or []
    else:
        assets = []

    now = datetime.utcnow()

    expiring_count = 0
    expired_count = 0
    certs_evaluated = 0
    total_assets = len(assets) if isinstance(assets, list) else 0
    sample_hosts = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue
        valid_to_raw = asset.get("ssl.valid_to")
        cert_date = parse_iso_date(valid_to_raw)
        if cert_date is None:
            continue
        certs_evaluated = certs_evaluated + 1
        days_until_expiry = (cert_date - now).days
        if days_until_expiry < 0:
            expired_count = expired_count + 1
        elif days_until_expiry <= 30:
            expiring_count = expiring_count + 1
            if len(sample_hosts) < 5:
                host = asset.get("bd.hostname") or asset.get("bd.original_hostname") or asset.get("id")
                sample_hosts.append(f"{host} (expires {valid_to_raw})")

    if certs_evaluated > 0:
        pass_reasons = [
            f"Evaluated {certs_evaluated} of {total_assets} inventory assets carrying an ssl.valid_to certificate expiration field.",
            f"{expiring_count} asset(s) have TLS certificates expiring within 30 days: {', '.join(sample_hosts) if sample_hosts else 'none'}.",
        ]
        fail_reasons = []
        recommendations = []
        if expiring_count > 0:
            recommendations = [
                "Renew TLS certificates for the internet-facing assets listed above before they expire to avoid service disruption or trust warnings."
            ]
    else:
        pass_reasons = []
        fail_reasons = [
            f"No assets among the {total_assets} inventory records carried a populated ssl.valid_to field to evaluate certificate expiration."
        ]
        recommendations = [
            "Verify that TLS metadata scanning is enabled in Tenable ASM so certificate expiration data is populated on inventory assets."
        ]

    result = {
        "certificateExpiringSoonCount": expiring_count,
        "totalAssetsEvaluated": total_assets,
        "certsWithExpirationData": certs_evaluated,
        "expiredCertificatesCount": expired_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAssets": total_assets,
            "certsWithExpirationData": certs_evaluated,
            "expiringWithin30Days": expiring_count,
            "alreadyExpired": expired_count,
        },
        metadata={
            "transformationId": "certificateExpiringSoonCount",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
