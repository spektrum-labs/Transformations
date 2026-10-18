"""Transformation: adminMfaEnrollmentPercentage (NinjaOne, GET /v2/users).

Value: a whole-number percentage, floor(100 * enabled technicians with mfaConfigured=true / enabled
technicians). Technicians (userType TECHNICIAN) are the accounts that sign in to the NinjaOne console;
end users are not counted. The pass bar lives in the requirement. mfaConfigured is the user's own MFA
enrolment as NinjaOne reports it, not a tenant policy, so this measures coverage, not enforcement.
A technician with no mfaConfigured field counts as without MFA. A body with no user records (an error,
an auth failure, an unrelated response) or no enabled technicians is not evaluated: dataCollection
error, no value.
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


def find_users(data):
    """The /v2/users list: a bare array of user objects, or one nested under a wrapper key."""
    if isinstance(data, list):
        if any(isinstance(u, dict) and "userType" in u for u in data):
            return data
        return None
    if isinstance(data, dict):
        for key in ("users", "data", "results", "items"):
            found = find_users(data.get(key))
            if found is not None:
                return found
    return None


def transform(input):
    data, validation = extract_input(input)
    users = find_users(data)
    technicians = []
    if users is not None:
        for u in users:
            if isinstance(u, dict) and str(u.get("userType", "")).upper() == "TECHNICIAN" and u.get("enabled") is not False:
                technicians.append(u)
    total = len(technicians)
    with_mfa = len([t for t in technicians if t.get("mfaConfigured") is True])
    without_mfa = total - with_mfa
    admins = [t for t in technicians if t.get("administrator") is True]
    admins_without_mfa = len([t for t in admins if t.get("mfaConfigured") is not True])

    # No user records, or no enabled technicians, is not evaluated (no value), never a 0.
    coverage = (with_mfa * 100) // total if total else None
    api_errors = []
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if users is None:
        api_errors = ["The response held no NinjaOne user records (userType field), so technician MFA could not be measured."]
        fail_reasons = list(api_errors)
    elif total == 0:
        api_errors = [f"NinjaOne returned {len(users)} user records but no enabled technicians, so technician MFA could not be measured."]
        fail_reasons = list(api_errors)
    else:
        if with_mfa:
            pass_reasons.append(f"{with_mfa} of {total} enabled technicians ({coverage}%) have MFA configured.")
        if without_mfa:
            fail_reasons.append(
                f"{without_mfa} of {total} enabled technicians have no MFA configured"
                + (f", including {admins_without_mfa} with system administrator rights." if admins_without_mfa else ".")
            )
            recommendations.append("Require MFA for every NinjaOne technician (Administration > Accounts > Technicians > Security).")

    result = {
        "adminMfaEnrollmentPercentage": coverage,
        "totalTechnicians": total,
        "techniciansWithMfa": with_mfa,
        "administratorsWithoutMfa": admins_without_mfa,
    }
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        api_errors=api_errors,
        input_summary={"totalUsers": len(users) if users is not None else 0, "enabledTechnicians": total},
        metadata={
            "transformationId": "adminMfaEnrollmentPercentage",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
