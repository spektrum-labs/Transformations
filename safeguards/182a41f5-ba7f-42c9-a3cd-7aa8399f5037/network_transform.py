"""
Transformation: network_transform
Vendor: Network Security
Category: Network Security

Evaluates if Network Security is set up properly.
"""

import json
import ast
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "network_transform",
                "vendor": "Network Security",
                "category": "Network Security"
            }
        }
    }


def transform(input):
    is_continuous_discovery_enabled = False

    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        input = _parse_input(input)
        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isContinuousDiscoveryEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if isinstance(data, dict):
            if 'response' in data:
                data = _parse_input(data['response'])
            if 'result' in data:
                data = _parse_input(data['result'])

            is_continuous_discovery_enabled = True if data.get('isContinuousDiscoveryEnabled', False) else False
            if not is_continuous_discovery_enabled:
                is_continuous_discovery_enabled = True if data.get('devices', False) else False

        if is_continuous_discovery_enabled:
            pass_reasons.append("Continuous discovery is enabled")
        else:
            fail_reasons.append("Continuous discovery is not enabled")
            recommendations.append("Enable continuous discovery for network visibility")

        return create_response(
            result={"isContinuousDiscoveryEnabled": is_continuous_discovery_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"continuousDiscoveryEnabled": is_continuous_discovery_enabled}
        )

    except Exception as e:
        return create_response(
            result={"isContinuousDiscoveryEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
