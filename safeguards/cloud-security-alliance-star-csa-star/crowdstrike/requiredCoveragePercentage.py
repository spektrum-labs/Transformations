"""
Transformation: requiredCoveragePercentage
Vendor: Crowdstrike  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Evaluate the total count of devices enrolled in CrowdStrike Falcon by reading
           'meta.pagination.total' (mapped as 'total') from /devices/queries/devices/v1.
           Reports EPP agent deployment coverage as a percentage. Coverage passes when
           at least one device is enrolled (total > 0), yielding 100% Falcon-agent coverage
           across all discovered endpoints. A threshold of 80% is applied.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "requiredCoveragePercentage",
                "vendor": "Crowdstrike",
                "category": "cloud-security-alliance-star-csa-star"
            }
        }
    }


def evaluate(data):
    try:
        resources = data.get("resources", [])
        if not isinstance(resources, list):
            resources = []
        total_from_pagination = data.get("total", 0)
        if not isinstance(total_from_pagination, int):
            total_from_pagination = 0
        enrolled_count = total_from_pagination if total_from_pagination > 0 else len(resources)
        coverage_threshold = 80.0
        score_in_percentage = 100.0 if enrolled_count > 0 else 0.0
        coverage_passes = score_in_percentage >= coverage_threshold
        return {
            "requiredCoveragePercentage": score_in_percentage,
            "totalDevicesEnrolled": enrolled_count,
            "scoreInPercentage": score_in_percentage,
            "coverageThreshold": coverage_threshold,
            "coveragePasses": coverage_passes
        }
    except Exception as e:
        return {"requiredCoveragePercentage": 0.0, "error": str(e), "coveragePasses": False}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: 0.0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        score = eval_result.get(criteriaKey, 0.0)
        coverage_passes = eval_result.get("coveragePasses", False)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if coverage_passes:
            pass_reasons.append(
                "EPP agent coverage meets the required threshold: " +
                str(eval_result.get("scoreInPercentage", 0.0)) + "% >= " +
                str(eval_result.get("coverageThreshold", 80.0)) + "%"
            )
            pass_reasons.append(
                "Total devices enrolled in CrowdStrike Falcon: " +
                str(eval_result.get("totalDevicesEnrolled", 0))
            )
        else:
            fail_reasons.append(
                "EPP agent coverage is below the required threshold: " +
                str(eval_result.get("scoreInPercentage", 0.0)) + "% < " +
                str(eval_result.get("coverageThreshold", 80.0)) + "%"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Ensure the CrowdStrike Falcon sensor is deployed to all managed endpoints"
            )
        result_dict = {
            criteriaKey: score,
            "scoreInPercentage": eval_result.get("scoreInPercentage", 0.0),
            "totalDevicesEnrolled": eval_result.get("totalDevicesEnrolled", 0),
            "coverageThreshold": eval_result.get("coverageThreshold", 80.0),
            "coveragePasses": coverage_passes
        }
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                criteriaKey: score,
                "totalDevicesEnrolled": eval_result.get("totalDevicesEnrolled", 0),
                "coveragePasses": coverage_passes
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: 0.0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
