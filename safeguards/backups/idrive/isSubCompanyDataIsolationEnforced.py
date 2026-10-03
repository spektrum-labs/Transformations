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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    company = {}
    if isinstance(data, dict):
        company = data
    elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        company = data[0]

    parent_company_id = company.get("company_id")
    sub_company_list = company.get("sub_company_list")
    if not isinstance(sub_company_list, list):
        sub_company_list = []

    fail_reasons = []
    pass_reasons = []
    recommendations = []

    if parent_company_id is None:
        fail_reasons.append("Response did not include a company_id for the queried company; cannot verify tenant scoping.")
        result_bool = False
    else:
        sub_ids = []
        for sub in sub_company_list:
            if isinstance(sub, dict):
                sub_ids.append(sub.get("company_id"))

        overlapping = [sid for sid in sub_ids if sid == parent_company_id]
        duplicate_ids = len(sub_ids) != len(set(sub_ids))

        if overlapping:
            fail_reasons.append(
                f"One or more sub_company_list entries share the parent company_id {parent_company_id}, "
                "indicating the response is not scoped distinctly per tenant."
            )
            result_bool = False
        elif duplicate_ids:
            fail_reasons.append(
                f"sub_company_list contains duplicate company_id values {sub_ids}, "
                "which is inconsistent with per-tenant data isolation."
            )
            result_bool = False
        else:
            result_bool = True
            if len(sub_ids) > 0:
                pass_reasons.append(
                    f"Company {parent_company_id} ('{company.get('name')}') query returned {len(sub_ids)} declared "
                    f"sub-companies with distinct company_id values ({sub_ids}), none matching the parent's own "
                    f"company_id, evidencing that the company_id-scoped query only surfaces the parent plus its "
                    "declared sub-companies rather than arbitrary sibling tenants."
                )
            else:
                pass_reasons.append(
                    f"Company {parent_company_id} ('{company.get('name')}') query returned an empty sub_company_list "
                    "and no sibling tenant data; the response is scoped strictly to the queried company_id, "
                    "consistent with enforced data isolation."
                )

    if not result_bool and not fail_reasons:
        fail_reasons.append("Unable to confirm sub-company data isolation from the getCompanySummary response.")

    if not result_bool:
        recommendations.append(
            "Verify the MSP company API enforces company_id scoping so sub_company_list never contains "
            "records sharing or duplicating the parent's own company_id."
        )

    input_summary = {
        "company_id": parent_company_id,
        "sub_company_count": len(sub_company_list),
    }

    return create_response(
        result={
            "isSubCompanyDataIsolationEnforced": result_bool,
            "companyId": parent_company_id,
            "subCompanyCount": len(sub_company_list),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSubCompanyDataIsolationEnforced",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
