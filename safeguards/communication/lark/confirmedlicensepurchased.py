"""
Transformation: confirmedLicensePurchased
Vendor: Lark
Category: Communication

Evaluates confirmedLicensePurchased for Lark (Bytedance)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Lark", "category": "Communication"}
        }
    }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        tenant = data.get("tenant", data.get("data", data))
        if isinstance(tenant, dict):
            status = tenant.get("status", "")
            active = tenant.get("active", False)
            tenant_name = tenant.get("name", tenant.get("display_name", "unknown"))
        else:
            status = data.get("status", "")
            active = data.get("active", False)
            tenant_name = data.get("name", "unknown")

        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "enabled", "normal"}
        result = status in valid_statuses or active is True

        # Lark returns code 0 on success; a valid tenant response implies active
        code = data.get("code", -1)
        if not result and code == 0 and tenant_name != "unknown":
            result = True
        # -- END EVALUATION LOGIC --

        return create_response(

            result={
            "confirmedLicensePurchased": result,
            "status": status,
            "tenantName": tenant_name
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
