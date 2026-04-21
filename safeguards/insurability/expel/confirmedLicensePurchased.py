"""
Transformation: confirmedLicensePurchased
Vendor: Expel  |  Category: insurability
Evaluates: Verifies that the Expel Workbench API key returns at least one valid
organization record, confirming an active Expel MDR license is purchased.
A non-empty 'data' array containing at least one organization entry in the
getOrganizations response confirms the customer is an active Expel subscriber.
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Expel",
                "category": "insurability"
            }
        }
    }


def evaluate(data):
    """
    Core evaluation logic for confirmedLicensePurchased.

    Inspects the merged getOrganizationData payload, which combines results
    from getOrganizations and getSecurityDevices (both return 'data' and 'meta').
    The organizations 'data' array is the authoritative signal: a non-empty list
    with at least one record whose type is 'organizations' (JSON:API convention)
    confirms the license. If the type field is absent, any non-empty record is
    treated as a valid organization entry, consistent with the API spec.
    """
    try:
        raw_data = data.get("data", [])

        if not isinstance(raw_data, list):
            return {
                "confirmedLicensePurchased": False,
                "error": "Expected 'data' to be a list but got: " + str(type(raw_data)),
                "totalRecords": 0,
                "organizationCount": 0
            }

        total_records = len(raw_data)

        # Filter to organization-type records (JSON:API 'type' field).
        # If no items carry a 'type' field at all, fall back to the full list
        # since we cannot distinguish — any record confirms the license.
        org_records = [item for item in raw_data if isinstance(item, dict) and item.get("type") == "organizations"]

        if total_records > 0 and len(org_records) == 0:
            # No typed records found — check if type field is simply absent
            typed_items = [item for item in raw_data if isinstance(item, dict) and "type" in item]
            if len(typed_items) == 0:
                # No type fields at all: treat all records as org records
                org_records = [item for item in raw_data if isinstance(item, dict)]

        organization_count = len(org_records)
        license_confirmed = organization_count > 0

        org_names = []
        for item in org_records:
            attrs = item.get("attributes", {})
            name = attrs.get("name", "") if isinstance(attrs, dict) else ""
            if name:
                org_names.append(name)

        return {
            "confirmedLicensePurchased": license_confirmed,
            "organizationCount": organization_count,
            "totalRecords": total_records,
            "organizationNames": org_names
        }

    except Exception as e:
        return {
            "confirmedLicensePurchased": False,
            "error": str(e),
            "organizationCount": 0,
            "totalRecords": 0
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
        additional_findings = []

        org_count = eval_result.get("organizationCount", 0)
        total_records = eval_result.get("totalRecords", 0)
        org_names = eval_result.get("organizationNames", [])

        if result_value:
            pass_reasons.append(
                "Expel Workbench API returned " + str(org_count) +
                " organization record(s), confirming an active Expel MDR license."
            )
            if org_names:
                additional_findings.append("Organization(s) found: " + ", ".join(org_names))
        else:
            fail_reasons.append(
                "No organization records were returned by the Expel Workbench API. "
                "This indicates no active Expel MDR license could be confirmed."
            )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Verify that the API key is valid and belongs to an active Expel subscriber. "
                "Ensure the service account has at least Read-only access to Organization Settings."
            )
            recommendations.append(
                "Contact Expel support if your organization should have an active MDR license "
                "but no organization records are being returned."
            )

        if total_records > 0 and org_count == 0:
            additional_findings.append(
                str(total_records) + " total record(s) returned but none matched type 'organizations'."
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                criteriaKey: result_value,
                "organizationCount": org_count,
                "totalRecords": total_records
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
