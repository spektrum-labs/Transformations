"""
Transformation: isPhishingRemediationConfigured
Vendor: NINJIO  |  Category: Security Awareness Training
Evaluates: Whether remedial training is configured for users who fail phishing simulations.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPhishingRemediationConfigured", "vendor": "NINJIO", "category": "Security Awareness Training"}
        }
    }


def _evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        simulations = (
            data.get("results") or
            data.get("data") or
            data.get("simulations") or
            data.get("items") or
            (data if isinstance(data, list) else [])
        )

        if not isinstance(simulations, list):
            simulations = [simulations] if simulations else []

        if not simulations:
            return {"isPhishingRemediationConfigured": False, "remediationSimulationCount": 0}

        # Indicators of remedial training configuration
        remediation_keywords = {
            "remedial", "remediation", "teachable", "teachable_moment",
            "phish_fail", "failed_phishing", "corrective", "followup", "follow_up",
            "catch_training", "phish_training"
        }

        remediation_count = 0
        for sim in simulations:
            if not isinstance(sim, dict):
                continue

            # Check simulation type
            sim_type = str(sim.get("type", sim.get("simulationType", sim.get("template_type", "")))).lower()
            # Check simulation name/title
            sim_name = str(sim.get("name", sim.get("title", sim.get("simulationName", "")))).lower()
            # Check for linked training/teachable moments
            has_linked_training = (
                sim.get("training_simulation_id") is not None or
                sim.get("trainingSimulationId") is not None or
                sim.get("teachable_moments_id") is not None or
                sim.get("teachableMomentsId") is not None or
                sim.get("remedial_training_id") is not None or
                sim.get("remedialTrainingId") is not None
            )

            is_remedial = (
                any(kw in sim_type for kw in remediation_keywords) or
                any(kw in sim_name for kw in remediation_keywords) or
                has_linked_training
            )

            if is_remedial:
                remediation_count += 1

        result = remediation_count > 0
    except Exception as e:
        return {"isPhishingRemediationConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPhishingRemediationConfigured"
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
        eval_result = _evaluate(data)

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
