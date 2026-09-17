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
        jobs = data
    else:
        jobs = data.get("data") or []

    total_jobs = len(jobs)

    tracked_records = []
    fully_identified_count = 0
    for job in jobs:
        if not isinstance(job, dict):
            continue
        job_id = job.get("id")
        base_model = job.get("model")
        fine_tuned_model = job.get("fine_tuned_model")
        status = job.get("status")
        tracked_records.append({
            "id": job_id,
            "model": base_model,
            "fine_tuned_model": fine_tuned_model,
            "status": status,
        })
        # a record is "fully identified" when it carries an id, base model,
        # and lifecycle status - the minimum fields an authoritative
        # inventory entry needs to be queryable and traceable.
        if job_id and base_model and status:
            fully_identified_count = fully_identified_count + 1

    # Evidence must come from the payload's actual content, not just from
    # the envelope existing. We require at least one fine-tuning job record
    # whose fields (id/model/status) are populated, demonstrating the
    # inventory endpoint actually carries traceable per-model metadata for
    # this org, not merely that the call succeeded.
    is_enforced = total_jobs > 0 and fully_identified_count == total_jobs and fully_identified_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enforced:
        sample_ids = [r.get("fine_tuned_model") or r.get("model") for r in tracked_records[:5]]
        pass_reasons.append(
            f"GET /v1/fine_tuning/jobs returned {total_jobs} model record(s), all {fully_identified_count} "
            f"carrying id, base model, and status fields (e.g. {sample_ids}); this evidences an "
            f"authoritative, queryable inventory of fine-tuned/custom models is maintained."
        )
    else:
        if total_jobs == 0:
            fail_reasons.append(
                "GET /v1/fine_tuning/jobs returned zero fine-tuning job records for this organization. "
                "There is no evidence of any tracked custom/fine-tuned model, so an enforced model "
                "inventory cannot be confirmed from this data."
            )
            recommendations.append(
                "If custom/fine-tuned models exist for this organization, ensure they are created via "
                "the fine_tuning/jobs API so they appear in this queryable inventory, or provide a "
                "separate authoritative model registry to evidence tracking."
            )
        else:
            fail_reasons.append(
                f"GET /v1/fine_tuning/jobs returned {total_jobs} record(s) but only {fully_identified_count} "
                f"carried complete id/model/status fields; the inventory data is incomplete and cannot be "
                f"treated as authoritative."
            )
            recommendations.append(
                "Investigate why some fine-tuning job records are missing id, model, or status fields; "
                "an authoritative inventory requires complete metadata on every tracked model."
            )

    result = {
        "isModelInventoryTrackingEnforced": is_enforced,
        "totalTrackedModels": total_jobs,
        "fullyIdentifiedModels": fully_identified_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalTrackedModels": total_jobs, "fullyIdentifiedModels": fully_identified_count},
        metadata={
            "transformationId": "isModelInventoryTrackingEnforced",
            "vendor": "OpenAI",
            "category": "artificial-intelligence",
        },
    )
