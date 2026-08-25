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
    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    active_rows = []
    for row in results:
        if not isinstance(row, dict):
            continue
        state = row.get("productState")
        if state == "ON":
            active_rows.append(row)

    total_active = len(active_rows)
    out_of_date_rows = [
        r for r in active_rows
        if str(r.get("definitionStatus", "")).strip().lower() != "up-to-date"
    ]
    out_of_date_count = len(out_of_date_rows)
    up_to_date_count = total_active - out_of_date_count

    is_up_to_date = total_active > 0 and out_of_date_count == 0

    input_summary = {
        "totalResultRows": len(results),
        "activeProductRows": total_active,
        "outOfDateRows": out_of_date_count,
        "upToDateRows": up_to_date_count,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_active == 0:
        fail_reasons.append(
            "No antivirus product rows report productState='ON' in the antivirus-status "
            "results, so signature currency cannot be confirmed for any active AV product."
        )
        recommendations.append(
            "Verify an antivirus product is actively enabled and reporting to NinjaOne on "
            "at least one device before evaluating signature freshness."
        )
    elif out_of_date_count == 0:
        sample_products = sorted(set(r.get("productName", "unknown") for r in active_rows))
        pass_reasons.append(
            f"All {total_active} active antivirus-status rows (products: {', '.join(sample_products)}) "
            f"report definitionStatus='Up-to-Date', with 0 out-of-date rows found."
        )
    else:
        sample = out_of_date_rows[:5]
        sample_desc = ", ".join(
            f"deviceId={r.get('deviceId')}/{r.get('productName')}={r.get('definitionStatus')}"
            for r in sample
        )
        fail_reasons.append(
            f"{out_of_date_count} of {total_active} active antivirus-status rows report a "
            f"definitionStatus other than 'Up-to-Date' (e.g. {sample_desc})."
        )
        recommendations.append(
            "Force a definition update or investigate connectivity for devices with stale "
            "antivirus signatures reported in the antivirus-status report."
        )

    result = {
        "isSignatureUpToDate": is_up_to_date,
        "activeProductRows": total_active,
        "outOfDateRows": out_of_date_count,
        "upToDateRows": up_to_date_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSignatureUpToDate",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
