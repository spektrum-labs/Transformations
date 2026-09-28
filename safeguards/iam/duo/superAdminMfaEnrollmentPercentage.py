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

    if isinstance(data, list):
        admins = data
    elif isinstance(data, dict):
        admins = data.get("response") or data.get("data") or []
        if not isinstance(admins, list):
            admins = []
    else:
        admins = []

    super_admin_roles = ["owner", "administrator"]
    super_admins = []
    for a in admins:
        if not isinstance(a, dict):
            continue
        role_id = (a.get("role_id") or "").lower()
        role = (a.get("role") or "").lower()
        if role_id in super_admin_roles or role in super_admin_roles:
            super_admins.append(a)

    total_super = len(super_admins)

    def is_mfa_enrolled(admin):
        phone_details = admin.get("phone_details") or []
        if isinstance(phone_details, list):
            for p in phone_details:
                if isinstance(p, dict) and p.get("activated") is True:
                    return True
        webauthn = admin.get("webauthncredentials") or []
        if isinstance(webauthn, list) and len(webauthn) > 0:
            return True
        hardtoken = admin.get("hardtoken")
        if hardtoken:
            return True
        return False

    enrolled_super_admins = [a for a in super_admins if is_mfa_enrolled(a)]
    enrolled_count = len(enrolled_super_admins)

    if total_super == 0:
        percentage = 0
    else:
        percentage = round((enrolled_count / total_super) * 100.0, 2)

    enrolled_names = [a.get("name") or a.get("email") or a.get("admin_id") for a in enrolled_super_admins]
    not_enrolled_names = [
        (a.get("name") or a.get("email") or a.get("admin_id"))
        for a in super_admins if a not in enrolled_super_admins
    ]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_super == 0:
        fail_reasons.append("No super admin (Owner/Administrator role) accounts were found in the getAdmins response.")
        recommendations.append("Verify that at least one Duo admin holds the Owner or Administrator role and has an MFA device enrolled.")
    elif enrolled_count == total_super:
        pass_reasons.append(
            f"All {total_super} super admin accounts ({', '.join([str(n) for n in enrolled_names])}) "
            f"have an active phone (activated=true), a registered webauthncredential, or a hardware token."
        )
    else:
        pass_reasons.append(
            f"{enrolled_count} of {total_super} super admin accounts have an enrolled MFA device."
        )
        fail_reasons.append(
            f"{total_super - enrolled_count} of {total_super} super admin accounts lack an enrolled MFA device: "
            f"{', '.join([str(n) for n in not_enrolled_names])}."
        )
        recommendations.append(
            "Enroll an MFA device (Duo Mobile push, phone callback, or WebAuthn security key) for each super admin account listed above."
        )

    result = {
        "superAdminMfaEnrollmentPercentage": percentage,
        "totalSuperAdmins": total_super,
        "enrolledSuperAdmins": enrolled_count,
    }

    input_summary = {
        "totalAdmins": len(admins),
        "totalSuperAdmins": total_super,
        "enrolledSuperAdmins": enrolled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "superAdminMfaEnrollmentPercentage",
            "vendor": "Duo",
            "category": "Multifactor Authentication",
        },
    )
