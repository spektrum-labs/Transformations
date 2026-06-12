"""
Transformation: isCodeExecutionEgressControlled
Vendor: Anthropic (Claude) Compliance API
Category: Network

Evaluates whether code-execution sandbox network egress is disabled.
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "isCodeExecutionEgressControlled"

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
                    "transformationId": "isCodeExecutionEgressControlled",
                    "vendor": "Anthropic",
                    "category": "Network"
                }
            }
        }

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        result_value = False

        rows = data.get("settings", []) if isinstance(data, dict) else []
        row = next((r for r in rows if isinstance(r, dict) and r.get("name") == "code_execution_network_egress_enabled"), None)
        if row is None:
            result_value = False
            fail_reasons.append("code_execution_network_egress_enabled not present; cannot attest control")
        else:
            egress = row.get("value", True)
            if isinstance(egress, str):
                egress = egress.strip().lower() in ("true", "yes", "1", "enabled", "on")
            result_value = not bool(egress)
            (pass_reasons if result_value else fail_reasons).append(
                "Code-execution egress %s" % ("controlled (disabled)" if result_value else "enabled"))

        return create_response(
            result={criteriaKey: result_value},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
