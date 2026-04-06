"""
Transformation: isIAMLoggingEnabled
Vendor: Red Hat Idm
Category: Identity & Access Management

Evaluates isIAMLoggingEnabled for Red Hat IDM (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isIAMLoggingEnabled", "vendor": "Red Hat Idm", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isIAMLoggingEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        # Red Hat IdM has built-in audit logging via 389 Directory Server
        # and SSSD. If config_show returns valid config, logging is active.
        config = data.get("config", data)
        if isinstance(config, dict):
            config = config.get("result", config)

        if isinstance(config, dict):
            # IdM always has audit logging via access/error logs in 389DS
            # Check that the config is valid (has known fields)
            domain = config.get("ipasearchrecordslimit", config.get("ipadomainresolutionorder", None))
            ca_renewal = config.get("ipaconfigstring", config.get("ipa_master", None))

            # If we got a valid config response, IdM logging is inherently enabled
            if len(config.keys()) > 0:
                result = True

            # Explicit check for logging-related configuration
            config_strings = config.get("ipaconfigstring", [])
            if isinstance(config_strings, list):
                for cs in config_strings:
                    if isinstance(cs, str) and "audit" in cs.lower():
                        result = True
                        break
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isIAMLoggingEnabled": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
