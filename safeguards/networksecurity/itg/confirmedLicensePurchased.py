"""\nTransformation: confirmedLicensePurchased\nVendor: ITG  |  Category: networksecurity\nEvaluates: Ensures a valid response is returned from the IT Glue organizations endpoint.\nA successful non-empty response confirms a valid, licensed IT Glue account is active.\n"""
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "ITG",
                "category": "networksecurity"
            }
        }
    }


def evaluate(data):
    """
    Pass when the organizations endpoint returns a non-empty list of records,
    confirming a valid, licensed IT Glue account is active.
    """
    try:
        organizations = data.get("data", None)

        if organizations is None:
            return {
                "confirmedLicensePurchased": False,
                "error": "No 'data' key found in API response from getOrganizations",
                "organizationCount": 0
            }

        if not isinstance(organizations, list):
            return {
                "confirmedLicensePurchased": False,
                "error": "Expected 'data' to be a list, but received an unexpected format",
                "organizationCount": 0
            }

        org_count = len(organizations)

        if org_count > 0:
            return {
                "confirmedLicensePurchased": True,
                "organizationCount": org_count
            }

        return {
            "confirmedLicensePurchased": False,
            "organizationCount": 0,
            "error": "IT Glue organizations list is empty; cannot confirm an active licensed account"
        }

    except Exception as e:
        return {
            "confirmedLicensePurchased": False,
            "error": str(e),
            "organizationCount": 0
        }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
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

        if result_value:
            pass_reasons.append(
                "IT Glue organizations endpoint returned a non-empty list, "
                "confirming a valid licensed account is active"
            )
            org_count = extra_fields.get("organizationCount", 0)
            pass_reasons.append("Total organizations found: " + str(org_count))
        else:
            fail_reasons.append(
                "IT Glue organizations endpoint did not return a valid non-empty response; "
                "license or account validity cannot be confirmed"
            )
            if "error" in eval_result:
                fail_reasons.append("Detail: " + eval_result["error"])
            recommendations.append(
                "Verify that the IT Glue API key is valid and has Administrator-level permissions"
            )
            recommendations.append(
                "Confirm the correct regional base URL is configured "
                "(https://api.itglue.com for US, https://api.eu.itglue.com for EU)"
            )
            recommendations.append(
                "Ensure at least one organization exists in IT Glue and is accessible via the API"
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "criteriaKey": criteriaKey,
                "resultValue": result_value,
                "organizationCount": extra_fields.get("organizationCount", 0)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
