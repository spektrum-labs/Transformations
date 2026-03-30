"""
Transformation: phishingClickRate
Vendor: KnowBe4  |  Category: Compliance Management
Evaluates: Organization-wide phish-prone percentage from KnowBe4
"""
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "phishingClickRate", "vendor": "KnowBe4", "category": "Compliance Management"}
        }
    }


def evaluate(data):
    """Core evaluation logic - extracts phish-prone percentage from campaign data."""
    try:
        campaigns = data if isinstance(data, list) else data.get('campaigns', [])
        if not campaigns:
            return {"phishingClickRate": "100", "phishPronePercentage": 100.0, "campaignsEvaluated": 0, "error": "No phishing campaigns found"}

        completed = [c for c in campaigns if c.get('status') in ('Closed', 'Completed')]
        if not completed:
            completed = campaigns

        most_recent = None
        most_recent_date = None
        for c in completed:
            last_run = c.get('last_run') or c.get('completed_date') or c.get('created_date')
            if last_run:
                try:
                    parsed = datetime.strptime(last_run, '%Y-%m-%dT%H:%M:%S.%fZ')
                except Exception:
                    try:
                        parsed = datetime.strptime(last_run, '%Y-%m-%dT%H:%M:%SZ')
                    except Exception:
                        continue
                if most_recent_date is None or parsed > most_recent_date:
                    most_recent_date = parsed
                    most_recent = c

        if most_recent is None:
            most_recent = completed[0]

        rate = most_recent.get('phish_prone_percentage', 100)
        return {
            "phishingClickRate": str(int(rate)),
            "phishPronePercentage": rate,
            "campaignName": most_recent.get('name', 'Unknown'),
            "campaignsEvaluated": len(completed)
        }
    except Exception as e:
        return {"phishingClickRate": "100", "phishPronePercentage": 100.0, "error": str(e)}


def transform(input):
    criteriaKey = "phishingClickRate"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review KnowBe4 configuration for {criteriaKey}")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
