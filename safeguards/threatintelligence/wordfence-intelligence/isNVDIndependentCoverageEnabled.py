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


KNOWN_FIELDS = [
    "id", "title", "software", "description", "references", "cwe", "cvss",
    "cve", "cve_link", "researchers", "published", "updated", "informational",
    "copyrights",
]


def get_records(data):
    """Normalize the Production Vulnerability Feed into a list of vulnerability records.

    The feed can arrive as:
      * a list of record dicts (array root)
      * a dict keyed by vulnerability UUID with record dicts as values
      * a columnar dict where each known field name maps to a parallel list
        (the shape captured for this tenant, currently empty arrays)
    """
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        keys = list(data.keys())
        if keys and set(keys).issubset(set(KNOWN_FIELDS)) and all(
            isinstance(v, list) for v in data.values()
        ):
            length = 0
            for v in data.values():
                lv = len(v) if isinstance(v, list) else 0
                if lv > length:
                    length = lv
            records = []
            for i in range(length):
                rec = {}
                for k in keys:
                    lst = data.get(k) or []
                    rec[k] = lst[i] if i < len(lst) else None
                records.append(rec)
            return records
        records = []
        for v in data.values():
            if isinstance(v, dict):
                records.append(v)
        return records
    return []


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    api_errors = []
    if isinstance(data, dict) and data.get("error"):
        api_errors.append(str(data.get("error")))

    records = get_records(data)
    total = len(records)

    independent_records = []
    for rec in records:
        cve = rec.get("cve")
        cve_link = rec.get("cve_link")
        has_cve = bool(cve) or bool(cve_link)
        if not has_cve:
            independent_records.append(rec)

    independent_count = len(independent_records)
    is_enabled = independent_count > 0

    sample_titles = [r.get("title") for r in independent_records[:3] if r.get("title")]

    if total == 0:
        fail_reasons = [
            "The Production Vulnerability Feed returned zero vulnerability records for "
            "this tenant's token, so no evidence of independent (non-CVE) coverage could "
            "be observed."
        ]
        recommendations = [
            "Verify the Wordfence Intelligence API token has access to the Production "
            "Feed and retry; an empty feed prevents confirming independent vulnerability "
            "coverage."
        ]
        pass_reasons = []
    elif is_enabled:
        pass_reasons = [
            f"{independent_count} of {total} records in the Production Vulnerability Feed "
            f"have no populated 'cve' or 'cve_link' field, indicating Wordfence tracks "
            f"vulnerabilities independently of/ahead of official CVE/NVD assignment."
        ]
        if sample_titles:
            pass_reasons.append(
                "Example independently-tracked records: " + "; ".join(sample_titles)
            )
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"All {total} records in the Production Vulnerability Feed carry a populated "
            f"'cve' or 'cve_link' field, showing no evidence of vulnerabilities tracked "
            f"independently of NVD/CVE assignment."
        ]
        recommendations = [
            "Confirm with Wordfence whether the Production Feed for this account includes "
            "vulnerabilities discovered ahead of CVE assignment; if not, independent "
            "coverage may require a different feed tier."
        ]

    result = {
        "isNVDIndependentCoverageEnabled": is_enabled,
        "totalVulnerabilities": total,
        "independentCoverageCount": independent_count,
    }

    input_summary = {
        "totalRecords": total,
        "independentRecords": independent_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "isNVDIndependentCoverageEnabled",
            "vendor": "Wordfence Intelligence",
            "category": "Threat Intelligence",
        },
    )
