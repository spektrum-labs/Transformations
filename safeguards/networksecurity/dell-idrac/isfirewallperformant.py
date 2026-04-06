"""
Transformation: isFirewallPerformant
Vendor: Dell Idrac
Category: Network Security

Evaluates isFirewallPerformant for Dell iDRAC (Network Security)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isFirewallPerformant", "vendor": "Dell Idrac", "category": "Network Security"}
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

        # Redfish /Systems/System.Embedded.1 returns Status with Health info
        # and ProcessorSummary / MemorySummary with utilization
        status_obj = data.get("Status", {})
        health = ""
        if isinstance(status_obj, dict):
            health = status_obj.get("Health", "")

        processor_summary = data.get("ProcessorSummary", {})
        memory_summary = data.get("MemorySummary", {})

        proc_health = ""
        mem_health = ""
        if isinstance(processor_summary, dict):
            proc_status = processor_summary.get("Status", {})
            if isinstance(proc_status, dict):
                proc_health = proc_status.get("Health", "")

        if isinstance(memory_summary, dict):
            mem_status = memory_summary.get("Status", {})
            if isinstance(mem_status, dict):
                mem_health = mem_status.get("Health", "")

        # All health indicators should be "OK" for performant status
        if isinstance(health, str) and health.lower() == "ok":
            if (not proc_health or proc_health.lower() == "ok") and (not mem_health or mem_health.lower() == "ok"):
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
