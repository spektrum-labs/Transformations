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


def parse_iso_date(s):
    if not s or not isinstance(s, str):
        return None
    try:
        date_part = s.split("T")[0]
        parts = date_part.split("-")
        if len(parts) != 3:
            return None
        year = int(parts[0])
        month = int(parts[1])
        day = int(parts[2])
        return (year, month, day)
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        vendors = data
    elif isinstance(data, dict):
        vendors = data.get("data") or data.get("results") or []
        if isinstance(vendors, dict):
            vendors = vendors.get("data") or []
    else:
        vendors = []

    if not isinstance(vendors, list):
        vendors = []

    now = datetime.utcnow()
    today = (now.year, now.month, now.day)

    managed_vendors = [v for v in vendors if isinstance(v, dict) and v.get("status") == "MANAGED"]
    total_managed = len(managed_vendors)

    covered = []
    not_covered_names = []

    for v in managed_vendors:
        name = v.get("name") or v.get("id") or "unknown vendor"
        last_review = v.get("lastSecurityReviewCompletionDate")
        next_due = v.get("nextSecurityReviewDueDate")

        has_completed_review = bool(last_review)

        next_due_parsed = parse_iso_date(next_due)
        is_overdue = False
        if next_due_parsed is not None and next_due_parsed < today:
            is_overdue = True

        if has_completed_review and not is_overdue:
            covered.append(name)
        else:
            not_covered_names.append(name)

    if total_managed > 0:
        coverage_pct = round((len(covered) / total_managed) * 100.0, 1)
    else:
        coverage_pct = 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_managed == 0:
        fail_reasons.append("No MANAGED vendors were found in the Vanta vendor registry, so coverage cannot be established.")
        recommendations.append("Mark relevant vendors as MANAGED in Vanta and complete their security reviews.")
    else:
        pass_reasons.append(
            f"{len(covered)} of {total_managed} MANAGED vendors have a completed security review "
            f"(non-null lastSecurityReviewCompletionDate) with a nextSecurityReviewDueDate that is not in the past: "
            f"{', '.join(covered) if covered else 'none'}."
        )
        if not_covered_names:
            fail_reasons.append(
                f"{len(not_covered_names)} of {total_managed} MANAGED vendors lack a completed, current security review: "
                f"{', '.join(not_covered_names)}."
            )
            recommendations.append(
                f"Complete security reviews for: {', '.join(not_covered_names)} and schedule their next review dates."
            )

    result = {
        "vendorRiskAssessmentCoveragePercentage": coverage_pct,
        "totalManagedVendors": total_managed,
        "coveredVendors": len(covered),
    }

    input_summary = {
        "totalManagedVendors": total_managed,
        "coveredVendors": len(covered),
        "notCoveredVendors": len(not_covered_names),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "vendorRiskAssessmentCoveragePercentage",
            "vendor": "Vanta Compliance Automation",
            "category": "compliance",
        },
    )
