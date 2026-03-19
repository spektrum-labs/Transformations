"""
Transformation: isRiskAssessmentCurrent
Vendor: ZenGRC  |  Category: GRC
Evaluates: Whether risk assessments are up to date with risks scored, categorized, and assigned to owners.
Source: GET /api/v2/risks
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRiskAssessmentCurrent", "vendor": "ZenGRC", "category": "GRC"}
        }
    }


def evaluate(data):
    """Check if risks are scored, categorized, and assigned to owners."""
    try:
        risks = data.get("data", data.get("risks", data.get("results", [])))
        if not isinstance(risks, list):
            risks = [risks] if risks else []

        total_risks = len(risks)
        scored_risks = 0
        risks_with_owners = 0
        categorized_risks = 0
        risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for risk in risks:
            if not isinstance(risk, dict):
                continue

            attrs = risk.get("attributes", risk)
            if not isinstance(attrs, dict):
                continue

            # Check risk scoring
            risk_score = attrs.get("risk_score", attrs.get("riskScore", attrs.get("score", attrs.get("inherent_risk", None))))
            risk_level = str(attrs.get("risk_level", attrs.get("riskLevel", attrs.get("severity", attrs.get("rating", ""))))).lower()

            if risk_score is not None or risk_level:
                scored_risks = scored_risks + 1

            if risk_level in risk_levels:
                risk_levels[risk_level] = risk_levels[risk_level] + 1

            # Check categorization
            category = attrs.get("category", attrs.get("risk_category", attrs.get("riskCategory", attrs.get("type", ""))))
            if category:
                categorized_risks = categorized_risks + 1

            # Check owner assignment
            owner = attrs.get("owner", attrs.get("owners", attrs.get("contact", attrs.get("assigned_to", None))))
            relationships = risk.get("relationships", {})
            if isinstance(relationships, dict):
                rel_owner = relationships.get("owners", relationships.get("contacts", None))
                if rel_owner:
                    owner = rel_owner
            if owner:
                risks_with_owners = risks_with_owners + 1

        has_risks = total_risks > 0
        has_scoring = scored_risks > 0
        is_current = has_risks and has_scoring

        return {
            "isRiskAssessmentCurrent": is_current,
            "totalRisks": total_risks,
            "scoredRisks": scored_risks,
            "risksWithOwners": risks_with_owners,
            "categorizedRisks": categorized_risks,
            "riskLevels": risk_levels
        }
    except Exception as e:
        return {"isRiskAssessmentCurrent": False, "error": str(e)}


def transform(input):
    criteriaKey = "isRiskAssessmentCurrent"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(str(extra_fields.get("totalRisks", 0)) + " risks tracked in ZenGRC")
            pass_reasons.append(str(extra_fields.get("scoredRisks", 0)) + " risks have been scored")
            if extra_fields.get("risksWithOwners", 0) > 0:
                pass_reasons.append(str(extra_fields["risksWithOwners"]) + " risks have assigned owners")
            levels = extra_fields.get("riskLevels", {})
            if levels.get("critical", 0) > 0 or levels.get("high", 0) > 0:
                additional = "Risk breakdown - Critical: " + str(levels.get("critical", 0)) + ", High: " + str(levels.get("high", 0)) + ", Medium: " + str(levels.get("medium", 0)) + ", Low: " + str(levels.get("low", 0))
                pass_reasons.append(additional)
        else:
            if extra_fields.get("totalRisks", 0) == 0:
                fail_reasons.append("No risks defined in ZenGRC")
                recommendations.append("Conduct a risk assessment and document risks in ZenGRC")
            else:
                fail_reasons.append("Risks exist but have not been scored or assessed")
                recommendations.append("Complete risk scoring and assign owners to all identified risks")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalRisks": extra_fields.get("totalRisks", 0), "scoredRisks": extra_fields.get("scoredRisks", 0)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
