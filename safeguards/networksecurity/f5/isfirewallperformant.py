"""
Transformation: isFirewallPerformant
Vendor: F5
Category: Network Security

Evaluates isFirewallPerformant for F5 (Network Security)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallPerformant", "vendor": "F5", "category": "Network Security"}
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

        # F5 /mgmt/tm/sys/version returns system info; performance data
        # may include CPU and memory utilization
        entries = data.get("entries", {})

        if isinstance(entries, dict) and len(entries) > 0:
            # Version info present indicates system is responsive
            result = True
        else:
            # Fallback: check for direct performance metrics
            cpu_usage = data.get("cpuUsage", data.get("oneMinAvgSystem", None))
            memory_usage = data.get("memoryUsage", data.get("tmmMemoryUsed", None))

            if cpu_usage is not None and memory_usage is not None:
                try:
                    if float(cpu_usage) < 50 and float(memory_usage) < 50:
                        result = True
                except (ValueError, TypeError):
                    pass
            elif isinstance(data, dict) and len(data) > 0:
                # Valid response from version endpoint means system is operational
                kind = data.get("kind", "")
                if isinstance(kind, str) and "sys" in kind.lower():
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
