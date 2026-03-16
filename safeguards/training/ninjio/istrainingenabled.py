"""
Transformation: isTrainingEnabled
Vendor: NINJIO  |  Category: Security Awareness Training
Evaluates: Whether at least one active training simulation (AWARE/SENSE/Compliance)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isTrainingEnabled", "vendor": "NINJIO", "category": "Security Awareness Training"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # Training simulations are returned as a list or under a 'results'/'data' key
        simulations = (
            data.get("results") or
            data.get("data") or
            data.get("simulations") or
            data.get("items") or
            (data if isinstance(data, list) else [])
        )

        if not isinstance(simulations, list):
            simulations = [simulations] if simulations else []

        total = len(simulations)
        if total == 0:
            return {"isTrainingEnabled": False, "activeSimulationCount": 0, "totalSimulations": 0}

        # Active statuses that indicate a running or scheduled training program
        active_statuses = {"active", "scheduled", "running", "in_progress", "enabled", "published", "live"}

        active_count = 0
        for sim in simulations:
            if not isinstance(sim, dict):
                continue
            status = str(sim.get("status", sim.get("state", sim.get("simulationStatus", "")))).lower()
            if status in active_statuses or status == "" :
                # If no status field, count existence as active (NINJIO returns
                # simulations only when they are scheduled or running)
                active_count += 1

        result = active_count > 0
        return {"isTrainingEnabled": result, "activeSimulationCount": active_count, "totalSimulations": total}
    except Exception as e:
        return {"isTrainingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isTrainingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Run core evaluation
        eval_result = evaluate(data)

        # Extract the boolean result and any extra fields
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
            recommendations.append(f"Review NINJIO configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
