"""
Transformation: isEnabled
Vendor: Okta  |  Category: mfa-validation
Evaluates: Whether at least one MFA factor has status ACTIVE at the org level.
The GET /api/v1/org/factors endpoint returns an array of factor objects each
containing 'id', 'provider', 'factorType', and 'status'. A pass result requires
at least one factor with status equal to ACTIVE.
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
                "transformationId": "isEnabled",
                "vendor": "Okta",
                "category": "mfa-validation"
            }
        }
    }


def evaluate(data):
    """
    Inspect the array returned by GET /api/v1/org/factors.
    Pass when at least one factor object has status == 'ACTIVE'.
    """
    try:
        # The API returns an array directly; the integration merges it under
        # 'getOrgFactors'. Handle both shapes.
        factors = []
        if isinstance(data, list):
            factors = data
        elif isinstance(data, dict):
            # Merged workflow result: look for a 'getOrgFactors' key first,
            # then fall back to common wrapper keys.
            for key in ["getOrgFactors", "data", "factors"]:
                candidate = data.get(key)
                if isinstance(candidate, list):
                    factors = candidate
                    break

        total_factors = len(factors)
        active_factors = []
        inactive_factors = []

        for factor in factors:
            status = factor.get("status", "")
            provider = factor.get("provider", "")
            factor_type = factor.get("factorType", "")
            factor_id = factor.get("id", "")
            label = provider + "/" + factor_type + " (" + factor_id + ")"
            if status == "ACTIVE":
                active_factors.append(label)
            else:
                inactive_factors.append(label + " [" + status + "]")

        is_enabled = len(active_factors) > 0

        return {
            "isEnabled": is_enabled,
            "totalFactors": total_factors,
            "activeFactorCount": len(active_factors),
            "inactiveFactorCount": len(inactive_factors),
            "activeFactors": active_factors,
            "inactiveFactors": inactive_factors
        }

    except Exception as e:
        return {"isEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        is_enabled = eval_result.get(criteria_key, False)

        total_factors = eval_result.get("totalFactors", 0)
        active_count = eval_result.get("activeFactorCount", 0)
        inactive_count = eval_result.get("inactiveFactorCount", 0)
        active_factors = eval_result.get("activeFactors", [])
        inactive_factors = eval_result.get("inactiveFactors", [])

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if is_enabled:
            pass_reasons.append(
                "At least one MFA factor is ACTIVE at the org level (" +
                str(active_count) + " of " + str(total_factors) + " factors active)."
            )
            if active_factors:
                pass_reasons.append("Active factors: " + ", ".join(active_factors))
            if inactive_factors:
                additional_findings.append(
                    "Inactive/not-enrolled factors: " + ", ".join(inactive_factors)
                )
        else:
            if total_factors == 0:
                fail_reasons.append(
                    "No MFA factors were returned by the Okta org factors endpoint."
                )
                recommendations.append(
                    "Navigate to Security > Authenticators in the Okta Admin Console "
                    "and enable at least one MFA factor for your organization."
                )
            else:
                fail_reasons.append(
                    "None of the " + str(total_factors) +
                    " MFA factor(s) returned have status ACTIVE."
                )
                recommendations.append(
                    "Activate at least one MFA factor in Security > Authenticators "
                    "within the Okta Admin Console."
                )
            if inactive_factors:
                additional_findings.append(
                    "Inactive/not-enrolled factors: " + ", ".join(inactive_factors)
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        result = {
            criteria_key: is_enabled,
            "totalFactors": total_factors,
            "activeFactorCount": active_count,
            "inactiveFactorCount": inactive_count
        }

        input_summary = {
            "totalFactorsReceived": total_factors,
            "activeFactorCount": active_count
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
