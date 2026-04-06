"""
Transformation: isURLRewriteEnabled
Vendor: Trellix Email Security
Category: Email Security

Evaluates isURLRewriteEnabled for Trellix Email Security (Email Security)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isURLRewriteEnabled", "vendor": "Trellix Email Security", "category": "Email Security"}
        }
    }


def transform(input):
    criteriaKey = "isURLRewriteEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        config = data.get("config", data.get("settings", data))
        url_rewrite = config.get("urlRewrite", config.get("url_rewrite", config.get("urlClickProtection", None)))
        if url_rewrite is True:
            result = True
        elif isinstance(url_rewrite, str) and url_rewrite.lower() in ("true", "enabled", "active"):
            result = True
        elif isinstance(url_rewrite, dict):
            enabled = url_rewrite.get("enabled", url_rewrite.get("status", False))
            if enabled is True or (isinstance(enabled, str) and enabled.lower() in ("enabled", "active")):
                result = True

        if not result:
            yara_rules = config.get("urlAnalysis", config.get("url_analysis", None))
            if yara_rules is True:
                result = True
            elif isinstance(yara_rules, str) and yara_rules.lower() in ("true", "enabled"):
                result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isURLRewriteEnabled": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
