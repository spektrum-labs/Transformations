"""
Transformation: isMDRConfigured
Vendor: MDR (mdr)  |  Category: MDR
Evaluates: Whether the MDR service has been fully configured in the vendor portal --
           authorised contacts set, threat response mode selected, integrations active.
           Reads the 'configured' field from the getMDRStatus response.
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
                "transformationId": "isMDRConfigured",
                "vendor": "mdr",
                "category": "MDR"
            }
        }
    }


def evaluate(data):
    try:
        configured = data.get("configured", False)
        enabled = data.get("enabled", False)
        service_active = data.get("serviceActive", False)
        status = data.get("status", "unknown")

        is_configured = bool(configured)

        return {
            "isMDRConfigured": is_configured,
            "configuredFlag": is_configured,
            "enabledFlag": bool(enabled),
            "serviceActive": bool(service_active),
            "serviceStatus": str(status)
        }
    except Exception as e:
        return {"isMDRConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMDRConfigured"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                "MDR service is fully configured with authorised contacts and threat response mode"
            )
            pass_reasons.append("configuredFlag: " + str(extra_fields.get("configuredFlag", False)))
        else:
            fail_reasons.append(
                "MDR service is not fully configured in the vendor portal"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Complete MDR configuration: set authorised contacts, select a threat response "
                "mode, and activate all required integrations in the vendor portal"
            )

        additional_findings.append("serviceStatus: " + str(extra_fields.get("serviceStatus", "unknown")))
        additional_findings.append("enabledFlag: " + str(extra_fields.get("enabledFlag", False)))
        additional_findings.append("serviceActive: " + str(extra_fields.get("serviceActive", False)))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "configuredFlag": extra_fields.get("configuredFlag"),
                "enabledFlag": extra_fields.get("enabledFlag"),
                "serviceStatus": extra_fields.get("serviceStatus")
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
