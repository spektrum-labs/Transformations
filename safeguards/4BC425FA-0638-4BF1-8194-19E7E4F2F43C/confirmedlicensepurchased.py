"""
Transformation: confirmedLicensePurchased
Vendor: AWS
Category: Backups / Licensing

Evaluates if the license has been purchased for the given Backup Provider.

AWS reports no licence or subscription for AWS Backup, which is pay-as-you-go, and no AWS API
returns a licensePurchased field. The field this transform used to read is synthesised by the
connector's returnSpec from the first DB instance of an RDS DescribeDBInstances call (a convert-to-bool
of that record, defaulting to false), so it only says whether the call returned an instance. That is not
licence evidence, so this check is always Not evaluated: None plus a dataCollection error that says why.
It is never True and never False.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "vendor": "AWS",
                "category": "Backups"
            }
        }
    }


NOT_EVIDENCE = (
    "AWS does not report a licence or subscription for AWS Backup, and no AWS API returns a licensePurchased "
    "field; the connector derives it from an RDS DescribeDBInstances record, so it is not licence evidence "
    "and this check cannot be evaluated from the AWS response"
)


def not_evaluated(validation, reason, transformation_errors=None, input_summary=None):
    """No value beside an error: the None reaches the evaluator as Not evaluated through the collection error."""
    return create_response(
        result={"confirmedLicensePurchased": None},
        validation=validation,
        transformation_errors=transformation_errors,
        api_errors=[reason],
        recommendations=["Confirm the backup licence or subscription with the vendor, or attach it as evidence"],
        input_summary=input_summary
    )


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(validation, "Could not read the response: input validation failed")

        # Whatever the connector put in licensePurchased (true, false or absent) is not an AWS statement
        # about a licence, so it is reported for the reviewer but never turned into a pass or a fail.
        synthesised = data.get("licensePurchased") if isinstance(data, dict) else None
        return not_evaluated(
            validation,
            NOT_EVIDENCE,
            input_summary={"licensePurchasedFieldSeen": synthesised is not None}
        )

    except Exception as e:
        # An error is Not evaluated, never a fail: None plus a dataCollection error.
        return not_evaluated(
            {"status": "error", "errors": [], "warnings": []},
            f"Transformation error: {str(e)}",
            transformation_errors=[str(e)])
