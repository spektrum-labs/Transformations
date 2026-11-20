import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for unused in range(3):
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
        apps = data
    elif isinstance(data, dict):
        apps = data.get("data") or data.get("apiResponse") or data.get("results") or []
    else:
        apps = []

    if not isinstance(apps, list):
        apps = []

    scores = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        grip_data = app.get("gripData") or {}
        if not isinstance(grip_data, dict):
            continue
        score = grip_data.get("riskScore")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            scores.append(score)

    total_apps = len(apps)
    scored_apps = len(scores)

    if scored_apps > 0:
        mean_score = sum(scores) / scored_apps
        max_score = max(scores)
    else:
        mean_score = sum(scores)
        max_score = sum(scores)

    mean_score_rounded = round(mean_score, 2)

    if scored_apps == 0:
        return create_response(
            result={
                "riskScore": mean_score_rounded,
                "meanRiskScore": mean_score_rounded,
                "maxRiskScore": max_score,
                "scoredApplications": scored_apps,
                "totalApplications": total_apps,
            },
            validation=validation,
            fail_reasons=[
                f"None of the {total_apps} SaaS applications returned by GET /public/saas carried a numeric gripData.riskScore (sum of observed scores={sum(scores)})."
            ],
            recommendations=[
                "Verify the Grip API key has read access to SaaS application risk data, or wait for Grip to complete risk scoring for discovered applications."
            ],
            input_summary={"totalApplications": total_apps, "scoredApplications": 0},
            metadata={
                "transformationId": "riskScore",
                "vendor": "Grip Security SaaS Platform",
                "category": "identity-and-access-management",
            },
        )

    pass_reasons = [
        f"Computed aggregate risk score from {scored_apps} of {total_apps} discovered SaaS applications with a numeric gripData.riskScore: mean={mean_score_rounded}, max={max_score}.",
        f"Highest individual application risk score observed was {max_score}."
    ]

    return create_response(
        result={
            "riskScore": mean_score_rounded,
            "meanRiskScore": mean_score_rounded,
            "maxRiskScore": max_score,
            "scoredApplications": scored_apps,
            "totalApplications": total_apps,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=[],
        input_summary={
            "totalApplications": total_apps,
            "scoredApplications": scored_apps,
            "meanRiskScore": mean_score_rounded,
            "maxRiskScore": max_score,
        },
        metadata={
            "transformationId": "riskScore",
            "vendor": "Grip Security SaaS Platform",
            "category": "identity-and-access-management",
        },
    )
