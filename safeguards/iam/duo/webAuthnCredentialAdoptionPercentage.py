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
        users = data
    elif isinstance(data, dict):
        users = data.get("response") or data.get("data") or []
        if not isinstance(users, list):
            users = []
    else:
        users = []

    total_users = len(users)
    users_with_webauthn = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        creds = u.get("webauthncredentials")
        if isinstance(creds, list) and len(creds) > 0:
            users_with_webauthn = users_with_webauthn + 1

    if total_users > 0:
        pct = round((users_with_webauthn / total_users) * 100.0, 2)
    else:
        pct = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    input_summary = {
        "totalUsers": total_users,
        "usersWithWebAuthnCredentials": users_with_webauthn,
    }

    if total_users == 0:
        fail_reasons.append(
            "No user records were returned by getUsers, so WebAuthn credential adoption cannot be computed."
        )
        recommendations.append(
            "Verify the Duo Admin API credential has permission to list users and retry."
        )
    elif users_with_webauthn > 0:
        pass_reasons.append(
            f"{users_with_webauthn} of {total_users} users ({pct}%) have a non-empty webauthncredentials array, "
            f"indicating a registered WebAuthn (FIDO2/passkey) credential."
        )
        if pct < 100.0:
            recommendations.append(
                f"Only {pct}% of users have registered a WebAuthn credential. "
                f"Encourage remaining users to enroll a FIDO2/passkey authenticator in the Duo Prompt."
            )
    else:
        fail_reasons.append(
            f"0 of {total_users} users have any entries in their webauthncredentials array; "
            f"no WebAuthn (FIDO2/passkey) credentials are registered across the tenant."
        )
        recommendations.append(
            "Enable and promote WebAuthn/passkey enrollment for users via Duo's authentication methods policy."
        )

    result = {
        "webAuthnCredentialAdoptionPercentage": pct,
        "totalUsers": total_users,
        "usersWithWebAuthnCredentials": users_with_webauthn,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "webAuthnCredentialAdoptionPercentage",
            "vendor": "Duo",
            "category": "iam",
        },
    )
