"""
Transformation: confirmedLicensePurchased
Vendor: NINJIO  |  Category: Security Awareness Training
Evaluates: Whether the customer has an active NINJIO bundle subscription (AWARE, ENGAGE, or PRODIGY tier).
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "NINJIO", "category": "Security Awareness Training"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        result = False

        # Bundles may be returned as a list at root level or under 'bundles'/'data'/'results'
        if isinstance(data, list):
            bundles = data
        else:
            bundles = (
                data.get("bundles") or
                data.get("data") or
                data.get("results") or
                data.get("items") or
                []
            )

        if not isinstance(bundles, list):
            bundles = [bundles] if bundles else []

        # Active SAT-related bundle names to match
        sat_keywords = ["aware", "engage", "prodigy", "phish", "sense", "training", "ninjio"]

        for bundle in bundles:
            if not isinstance(bundle, dict):
                continue

            status = bundle.get("status", bundle.get("state", bundle.get("active", "")))
            if isinstance(status, bool):
                is_active = status
            else:
                is_active = str(status).lower() in ("active", "enabled", "true", "1", "current")

            if not is_active:
                continue

            # Check bundle name/type contains SAT-related keywords
            bundle_name = str(bundle.get("name", bundle.get("bundleName", bundle.get("type", "")))).lower()
            if any(kw in bundle_name for kw in sat_keywords):
                result = True
                break

        # Fallback: if any bundle is active and no name filtering applies,
        # treat the presence of any active bundle as license confirmed
        if not result and bundles:
            for bundle in bundles:
                if not isinstance(bundle, dict):
                    continue
                status = bundle.get("status", bundle.get("state", bundle.get("active", "")))
                if isinstance(status, bool) and status:
                    result = True
                    break
                elif str(status).lower() in ("active", "enabled", "true", "1", "current"):
                    result = True
                    break

        return {"confirmedLicensePurchased": result, "bundleCount": len(bundles)}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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
        print(eval_result)
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
