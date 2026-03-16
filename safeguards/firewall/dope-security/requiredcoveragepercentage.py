"""
Transformation: requiredCoveragePercentage
Vendor: Dope Security  |  Category: Firewall
Evaluates: The percentage of enrolled endpoints that have the dope.swg agent
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "Dope Security", "category": "Firewall"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    COVERAGE_THRESHOLD = 95.0

    try:
        api_data = data.get("data", data)
        endpoints = api_data.get("endpoints", [])
        page_info = api_data.get("pageInfo", {})

        # Warn if there are more pages that may not have been fetched
        has_next_page = page_info.get("hasNextPage", False)
        pagination_warning = None
        if has_next_page:
            pagination_warning = "WARNING: hasNextPage=true detected. Coverage calculation may be incomplete — ensure all pages are fetched before evaluating."

        if not isinstance(endpoints, list):
            return {"requiredCoveragePercentage": False, "error": "Unexpected endpoints format"}

        total = len(endpoints)
        if total == 0:
            return {
                "requiredCoveragePercentage": False,
                "coveragePercent": 0.0,
                "protectedEndpoints": 0,
                "totalEndpoints": 0,
                "reason": "No endpoints enrolled"
            }

        protected = 0
        unprotected_names = []

        for ep in endpoints:
            status = ep.get("status", "").lower()
            admin_state = ep.get("adminSetState", {})

            if isinstance(admin_state, dict):
                enabled = admin_state.get("enabled", False)
            else:
                enabled = bool(admin_state)

            if isinstance(enabled, str):
                enabled = enabled.lower() in ("true", "yes", "1", "enabled")

            is_protected = (status == "healthy" and bool(enabled))

            if is_protected:
                protected += 1
            else:
                device_name = ep.get("deviceName", ep.get("emailId", "unknown"))
                unprotected_names.append(f"{device_name} (status={status})")

        coverage = (protected / total) * 100
        result = coverage >= COVERAGE_THRESHOLD
    except Exception as e:
        return {"requiredCoveragePercentage": False, "error": str(e)}


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
            recommendations.append(f"Review Dope Security configuration for {criteriaKey}")

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
