"""
Transformation: isDMARCConfigured
Vendor: Proofpoint  |  Category: Email Security
Evaluates: anti_spoofing feature is enabled.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isDMARCConfigured", "vendor": "Proofpoint", "category": "Email Security"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    try:
        # `bool(data)` asked whether a response arrived, not what it said, so any
        # non-empty body -- including one describing the feature as OFF -- satisfied
        # this criterion and no input could make it false. Resolved from the named
        # feature flag(s) now; see affirmative_signal below.
        result = affirmative_signal(data, ['anti_spoofing', 'antiSpoofing'], require_all=False)
        return {"isDMARCConfigured": result}

    except Exception as e:
        return {"isDMARCConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isDMARCConfigured"
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
            recommendations.append(f"Review Proofpoint configuration for {criteriaKey}")

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


def affirmative_signal(data, feature_keys, require_all=False):
    """True only when the payload POSITIVELY evidences the named feature(s).

    Replaces `result = bool(data)`, which asked whether a response arrived rather than
    what it said -- so ANY non-empty body, including one describing the feature as OFF,
    satisfied the criterion and no input could ever make it false. Measured 2026-09-21.

    Looks for feature_keys at the top level and inside common nested containers
    (features/settings/config/policies/result). An explicit OFF for any checked key
    beats everything. With require_all, every key must evidence ON; otherwise any one
    doing so is enough. Anything unread, empty, erroring or unrecognised -> False
    (never True by default).
    """
    if not isinstance(data, dict) or not data:
        return False
    for err_key in ("error", "errors", "errorMessage", "errorType", "fault"):
        if data.get(err_key):
            return False
    containers = [data]
    for nest_key in ("features", "settings", "featureSettings", "configuration",
                     "config", "policies", "data", "result"):
        nested = data.get(nest_key)
        if isinstance(nested, dict):
            containers.append(nested)
    off_words = ("false", "disabled", "off", "inactive", "none")
    on_words = ("true", "enabled", "on", "active", "yes")

    def signal(key):
        for container in containers:
            if key in container:
                value = container[key]
                if value is False:
                    return False
                if isinstance(value, str) and value.strip().lower() in off_words:
                    return False
                if value is True:
                    return True
                if isinstance(value, str) and value.strip().lower() in on_words:
                    return True
                if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
                    return True
                return None  # present but an unrecognised shape -- not a signal either way
        return None  # key not present at all

    signals = [signal(k) for k in feature_keys]
    if any(s is False for s in signals):
        return False
    if require_all:
        return bool(signals) and all(s is True for s in signals)
    return any(s is True for s in signals)
