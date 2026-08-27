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
    if not isinstance(data, (dict, list)):
        data = {}

    transformation_errors = []

    # The Wordfence Production Vulnerability Feed returns a columnar
    # (struct-of-arrays) JSON body: {"id": [...], "cwe": [...], ...}
    # where each top-level key holds a parallel array, one entry per
    # vulnerability record, aligned by index. Handle both this shape
    # and a defensive fallback list-of-records shape.
    ids = []
    cwe_entries = []

    if isinstance(data, dict):
        raw_ids = data.get("id")
        raw_cwe = data.get("cwe")
        ids = raw_ids if isinstance(raw_ids, list) else []
        cwe_entries = raw_cwe if isinstance(raw_cwe, list) else []
    elif isinstance(data, list):
        # fallback: list-of-record shape, one dict per vulnerability
        ids = [rec.get("id") for rec in data if isinstance(rec, dict)]
        cwe_entries = [rec.get("cwe") for rec in data if isinstance(rec, dict)]

    total_records = len(ids)

    def has_cwe(entry):
        if isinstance(entry, dict):
            cwe_id = entry.get("id")
            cwe_name = entry.get("name")
            return bool(cwe_id) or bool(cwe_name)
        return bool(entry)

    records_with_cwe = 0
    for entry in cwe_entries:
        if has_cwe(entry):
            records_with_cwe = records_with_cwe + 1

    input_summary = {
        "totalRecords": total_records,
        "recordsWithCwe": records_with_cwe,
        "cweEntriesReturned": len(cwe_entries),
    }

    if total_records == 0:
        # No vulnerability records were returned in this feed pull, so
        # CWE tagging coverage cannot be confirmed from this response.
        is_enabled = False
        pass_reasons = []
        fail_reasons = [
            "The production vulnerability feed returned zero records "
            "(id array length 0), so no 'cwe' field values could be "
            "inspected to confirm CWE classification is populated."
        ]
        recommendations = [
            "Re-run this check against a feed pull that includes "
            "vulnerability records, or verify the API token has access "
            "to the production feed contents."
        ]
    elif records_with_cwe == total_records:
        is_enabled = True
        pass_reasons = [
            f"All {total_records} vulnerability records in the production "
            f"feed carry a populated 'cwe' object with a non-empty id/name "
            f"({records_with_cwe} of {total_records} records verified)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_enabled = False
        pass_reasons = []
        fail_reasons = [
            f"Only {records_with_cwe} of {total_records} vulnerability "
            f"records in the production feed carry a populated 'cwe' "
            f"object; the remaining {total_records - records_with_cwe} "
            f"records have an empty or missing CWE classification."
        ]
        recommendations = [
            "Investigate why some vulnerability records lack a CWE "
            "classification and confirm with Wordfence Intelligence "
            "whether classification is still in progress for those IDs."
        ]

    result = {
        "isCWEClassificationEnabled": is_enabled,
        "totalRecords": total_records,
        "recordsWithCwe": records_with_cwe,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "isCWEClassificationEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "threatintelligence",
        },
    )
