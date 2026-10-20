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
        documents = data
    elif isinstance(data, dict):
        documents = data.get("data") or data.get("results") or []
        if isinstance(documents, dict):
            documents = documents.get("data") or []
    else:
        documents = []

    if not isinstance(documents, list):
        documents = []

    stale_statuses = ["Needs document", "Needs update"]

    stale_docs = []
    for doc in documents:
        if not isinstance(doc, dict):
            continue
        status = doc.get("uploadStatus") or ""
        if status in stale_statuses:
            stale_docs.append(doc)

    total_docs = len(documents)
    stale_count = len(stale_docs)

    stale_titles = [d.get("title") or d.get("id") or "unknown" for d in stale_docs][:10]

    api_errors = []
    transformation_errors = []

    if total_docs == 0:
        fail_reasons = []
        pass_reasons = []
        recommendations = []
        if not documents:
            fail_reasons.append("No compliance documents were returned by getDocuments; unable to confirm evidence freshness.")
    else:
        pass_reasons = []
        fail_reasons = []
        recommendations = []

    if stale_count > 0:
        fail_reasons.append(
            f"{stale_count} of {total_docs} compliance documents are stale (status in {stale_statuses}): examples {stale_titles}."
        )
        recommendations.append(
            "Upload missing evidence or refresh expired documents for: " + ", ".join(stale_titles)
        )
    else:
        pass_reasons.append(
            f"All {total_docs} compliance documents report a non-stale uploadStatus (none in {stale_statuses})."
        )

    result = {
        "staleEvidenceArtifactsCount": stale_count,
        "totalDocuments": total_docs,
    }

    input_summary = {
        "totalDocuments": total_docs,
        "staleDocuments": stale_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "staleEvidenceArtifactsCount",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
        api_errors=api_errors,
        transformation_errors=transformation_errors,
    )
