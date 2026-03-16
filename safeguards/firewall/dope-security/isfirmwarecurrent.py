"""
Transformation: isFirmwareCurrent
Vendor: Dope Security  |  Category: Firewall
Evaluates: Whether all enrolled dope.endpoint agents are running a supported
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirmwareCurrent", "vendor": "Dope Security", "category": "Firewall"}
        }
    }


def evaluate(data):
    """Core evaluation logic extracted from doc transform."""
    # Update this as Dope Security releases new versions.
    # Check https://inflight.dope.security/release-notes for latest.
    MINIMUM_SUPPORTED_VERSION = "3.0.0"

    def parse_version(version_str):
        """Parse a version string into a comparable tuple of ints."""
        if not version_str:
            return (0, 0, 0)
        parts = str(version_str).split(".")
        result = []
        for part in parts[:3]:  # take first 3 segments only
            try:
                result.append(int(part))
            except ValueError:
                result.append(0)
        while len(result) < 3:
            result.append(0)
        return tuple(result)

    min_version_tuple = parse_version(MINIMUM_SUPPORTED_VERSION)

    # Parse input
    data = parse_input(input)

    # Standard response unwrapping chain
    data = data.get("response", data)
    data = data.get("result", data)
    data = data.get("apiResponse", data)


    def parse_version(version_str):
                """Parse a version string into a comparable tuple of ints."""
                if not version_str:
                    return (0, 0, 0)
                parts = str(version_str).split(".")
                result = []
                for part in parts[:3]:  # take first 3 segments only
                    try:
                        result.append(int(part))
                    except ValueError:
                        result.append(0)
                while len(result) < 3:
                    result.append(0)
                return tuple(result)
    min_version_tuple = parse_version(MINIMUM_SUPPORTED_VERSION)

    try:
        api_data = data.get("data", data)
        endpoints = api_data.get("endpoints", [])

        if not isinstance(endpoints, list):
            return {"isFirmwareCurrent": False, "error": "Unexpected endpoints format"}

        total = len(endpoints)
        if total == 0:
            return {
                "isFirmwareCurrent": False,
                "outdatedEndpoints": [],
                "outdatedCount": 0,
                "totalEndpoints": 0,
                "minimumVersionThreshold": MINIMUM_SUPPORTED_VERSION,
                "reason": "No endpoints enrolled"
            }

        outdated = []
        for ep in endpoints:
            agent_version = ep.get("agentVersion", "")
            device_name = ep.get("deviceName", ep.get("emailId", "unknown"))

            if not agent_version:
                # Unknown version — treat as outdated
                outdated.append(f"{device_name} (version=unknown)")
                continue

            ep_version_tuple = parse_version(agent_version)
            if ep_version_tuple < min_version_tuple:
                outdated.append(f"{device_name} (version={agent_version})")

        result = len(outdated) == 0
    except Exception as e:
        return {"isFirmwareCurrent": False, "error": str(e)}


def transform(input):
    criteriaKey = "isFirmwareCurrent"
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
