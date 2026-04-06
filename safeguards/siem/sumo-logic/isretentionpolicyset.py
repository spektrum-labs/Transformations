"""
Transformation: isRetentionPolicySet
Vendor: Sumo Logic
Category: SIEM

Evaluates isRetentionPolicySet for Sumo Logic SIEM
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRetentionPolicySet", "vendor": "Sumo Logic", "category": "SIEM"}
        }
    }


def transform(input):
    criteriaKey = "isRetentionPolicySet"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # Sumo Logic account status includes plan and retention details
        plan_type = data.get("planType", data.get("pricingModel", ""))
        retention_days = data.get("retentionDays", data.get("defaultDataRetentionDays", None))
        account_status = data.get("accountStatus", data.get("status", ""))

        if retention_days is not None:
            result = int(retention_days) > 0
            info = str(retention_days) + " days"
        elif plan_type:
            result = True
            info = "plan: " + str(plan_type)
        elif account_status:
            result = str(account_status).lower() in ("active", "ok", "enabled")
            info = "account " + str(account_status)
        else:
            result = bool(data) and "error" not in str(data).lower()
            info = "status retrieved" if result else "unknown"

        return create_response(

            result={
            "isRetentionPolicySet": result,
            "retentionInfo": info
        },

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
