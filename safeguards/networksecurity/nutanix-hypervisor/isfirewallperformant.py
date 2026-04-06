"""
Transformation: isFirewallPerformant
Vendor: Nutanix Hypervisor
Category: Network Security

Evaluates isFirewallPerformant for Nutanix Hypervisor (Network Security)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallPerformant", "vendor": "Nutanix Hypervisor", "category": "Network Security"}
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

        # Nutanix clusters/list returns entities with resource utilization stats
        entities = data.get("entities", [])
        if isinstance(entities, list) and len(entities) > 0:
            all_healthy = True
            for entity in entities:
                if isinstance(entity, dict):
                    status = entity.get("status", {})
                    if isinstance(status, dict):
                        resources = status.get("resources", {})
                        stats = resources.get("stats", {})
                        cpu = stats.get("hypervisor_cpu_usage_ppm", None)
                        mem = stats.get("hypervisor_memory_usage_ppm", None)
                        if cpu is not None and mem is not None:
                            try:
                                # ppm = parts per million; 500000 = 50%
                                if float(cpu) >= 500000 or float(mem) >= 500000:
                                    all_healthy = False
                                    break
                            except (ValueError, TypeError):
                                all_healthy = False
                                break
            if all_healthy:
                result = True
        elif isinstance(data, dict) and data.get("status", "").lower() in ("ok", "healthy"):
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
