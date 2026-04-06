"""
Transformation: hasBlockPageConfigured
Vendor: DNSFilter
Category: Network Security

Verifies custom block pages are configured for user notification.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "hasBlockPageConfigured", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "hasBlockPageConfigured"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        block_pages = data if isinstance(data, list) else []
        if isinstance(data, dict):
            block_pages = data.get("blockPages", data.get("block_pages", []))

        enabled_count = 0
        for page in block_pages:
            if isinstance(page, dict) and page.get("enabled", True):
                enabled_count = enabled_count + 1

        has_configured = enabled_count > 0

        if has_configured:
            pass_reasons.append(f"{enabled_count} custom block page(s) configured")
        else:
            fail_reasons.append("No custom block pages configured")
            recommendations.append("Configure custom block pages in DNSFilter for user notification")

        return create_response(
            result={criteriaKey: has_configured, "blockPageCount": enabled_count, "totalBlockPages": len(block_pages)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"enabledBlockPages": enabled_count, "totalBlockPages": len(block_pages)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
