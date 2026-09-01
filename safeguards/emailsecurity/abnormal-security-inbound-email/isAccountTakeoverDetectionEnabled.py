import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    """Create the standardized 5-section transformation response."""
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

    if isinstance(data, list):
        cases = data
    elif isinstance(data, dict):
        cases = data.get("cases") or data.get("data") or []
        if not isinstance(cases, list):
            cases = []
    else:
        cases = []

    total_cases = len(cases)

    sign_in_case_ids = []
    other_ato_case_ids = []

    for c in cases:
        if not isinstance(c, dict):
            continue
        case_id = c.get("caseId") or c.get("case_id") or "unknown"
        analysis = c.get("analysis")
        severity = c.get("severity") or c.get("severity_level") or ""
        description = c.get("description") or ""

        analysis_text = ""
        if isinstance(analysis, list):
            analysis_text = " ".join([str(a) for a in analysis])
        elif analysis:
            analysis_text = str(analysis)

        combined = (analysis_text + " " + str(severity) + " " + str(description)).upper()

        if "SIGN_IN" in combined or "SIGN-IN" in combined or "SIGNIN" in combined:
            sign_in_case_ids.append(case_id)
        elif "ACCOUNT TAKEOVER" in combined or "ATO" in combined:
            other_ato_case_ids.append(case_id)

    is_enabled = len(sign_in_case_ids) > 0

    input_summary = {
        "totalCases": total_cases,
        "signInClassificationCases": len(sign_in_case_ids),
        "otherAccountTakeoverCases": len(other_ato_case_ids),
    }

    if is_enabled:
        pass_reasons = [
            f"Found {len(sign_in_case_ids)} case(s) out of {total_cases} total with a SIGN_IN "
            f"analysis classification (example case id: {sign_in_case_ids[0]}), evidencing active "
            "account takeover detection based on anomalous authentication behavior."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_cases == 0:
            fail_reasons = [
                "The /v1/cases endpoint returned 0 cases for this tenant, so no SIGN_IN analysis "
                "classification could be observed to confirm active account takeover detection."
            ]
            recommendations = [
                "Confirm the Abnormal Security subscription includes the Account Takeover product "
                "and that case records are being generated for this tenant."
            ]
        else:
            fail_reasons = [
                f"Inspected {total_cases} case(s) but none carried a SIGN_IN analysis classification "
                f"(found {len(other_ato_case_ids)} case(s) with other account-takeover-related text), "
                "so anomalous authentication detection could not be confirmed from this data."
            ]
            recommendations = [
                "Verify Account Takeover detection is enabled and review case analysis fields for "
                "SIGN_IN classification coverage."
            ]

    result = {
        "isAccountTakeoverDetectionEnabled": is_enabled,
        "totalCases": total_cases,
        "signInClassificationCases": len(sign_in_case_ids),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAccountTakeoverDetectionEnabled",
            "vendor": "Abnormal Security Inbound Email",
            "category": "emailsecurity",
        },
    )
