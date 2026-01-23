"""
Transformation: asm_transform
Vendor: Attack Surface Management
Category: Security / ASM

Transforms Attack Surface Management data to check if ASM is enabled and logging.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "asm_transform",
                "vendor": "Attack Surface Management",
                "category": "Security"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isASMEnabled": False, "isASMLoggingEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        default_value = data is not None

        if isinstance(data, dict) and 'errors' in data:
            default_value = False

        is_asm_enabled = False
        is_asm_logging_enabled = False

        if isinstance(data, dict):
            is_asm_enabled = data.get('isASMEnabled', default_value)
            is_asm_logging_enabled = data.get('isASMLoggingEnabled', default_value)

            if 'SCHEDULED_SCAN_LIST_OUTPUT' in data:
                scheduled_scan_list_output = data.get('SCHEDULED_SCAN_LIST_OUTPUT', {}).get("RESPONSE", {}).get("SCHEDULED_SCAN_LIST", {}).get("SCAN", [])

                if scheduled_scan_list_output and len(scheduled_scan_list_output) > 0:
                    is_asm_enabled = True
                    is_asm_logging_enabled = True

        if is_asm_enabled:
            pass_reasons.append("Attack Surface Management is enabled")
        else:
            fail_reasons.append("Attack Surface Management is not enabled")
            recommendations.append("Enable Attack Surface Management for visibility into your external attack surface")

        if is_asm_logging_enabled:
            pass_reasons.append("ASM logging is enabled")
        else:
            fail_reasons.append("ASM logging is not enabled")
            recommendations.append("Enable ASM logging for audit and compliance")

        return create_response(
            result={
                "isASMEnabled": is_asm_enabled,
                "isASMLoggingEnabled": is_asm_logging_enabled
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "asmEnabled": is_asm_enabled,
                "asmLoggingEnabled": is_asm_logging_enabled
            }
        )

    except Exception as e:
        return create_response(
            result={"isASMEnabled": False, "isASMLoggingEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
