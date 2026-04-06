"""
Transformation: isFirewallPerformant
Vendor: Fastly
Category: Network Security

Evaluates isFirewallPerformant for Fastly (Network Security)
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallPerformant", "vendor": "Fastly", "category": "Network Security"}
        }
    }


def transform(input):
    criteriaKey = "isFirewallPerformant"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # Fastly /service returns services; an active service list indicates
        # the edge platform is operational and responsive
        if isinstance(data, list) and len(data) > 0:
            # Check that services have active versions (deployments)
            for svc in data:
                if isinstance(svc, dict):
                    active_version = svc.get("active_version", None)
                    if active_version is not None:
                        result = True
                        break
        elif isinstance(data, dict):
            # Check for error ratios in stats or healthy service status
            error_rate = data.get("errors", data.get("error_rate", None))
            status_val = data.get("status", "")

            if error_rate is not None:
                try:
                    if float(error_rate) < 50:
                        result = True
                except (ValueError, TypeError):
                    pass
            elif isinstance(status_val, str) and status_val.lower() in ("ok", "healthy", "active"):
                result = True
            elif len(data) > 0:
                result = True

        # -- END EVALUATION LOGIC --

        return create_response(

            result={"isFirewallPerformant": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
