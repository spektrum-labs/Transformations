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


def transform_evidence(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        apps = data
    elif isinstance(data, dict):
        apps = data.get("results") or data.get("data") or data.get("applications") or []
        if not isinstance(apps, list):
            apps = []
    else:
        apps = []

    real_sso_types = ["saml", "saml2", "oidc"]

    total_apps = len(apps)
    sso_apps = []
    active_sso_apps = []

    for app in apps:
        if not isinstance(app, dict):
            continue
        sso = app.get("sso")
        if not isinstance(sso, dict):
            continue
        sso_type = sso.get("type")
        if sso_type in real_sso_types:
            sso_apps.append(app)
            if sso.get("active") is True:
                active_sso_apps.append(app)

    is_sso_enabled = len(active_sso_apps) > 0

    sample_names = [
        a.get("displayLabel") or a.get("displayName") or a.get("name") or a.get("_id")
        for a in active_sso_apps[:5]
    ]

    if is_sso_enabled:
        pass_reasons = [
            f"Found {len(active_sso_apps)} active SAML/OIDC SSO application(s) out of {total_apps} total applications configured (sso.type in {real_sso_types}, sso.active=true). Examples: {sample_names}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No active SAML/OIDC SSO applications found among {total_apps} configured applications ({len(sso_apps)} apps had a saml/oidc sso.type but none were active)."
        ]
        recommendations = [
            "Configure and activate at least one SAML or OIDC SSO application in JumpCloud's Applications catalog to enable single sign-on."
        ]

    result = {
        "isSSOEnabled": is_sso_enabled,
        "totalApplications": total_apps,
        "ssoConfiguredApplications": len(sso_apps),
        "activeSSOApplications": len(active_sso_apps),
    }

    input_summary = {
        "totalApplications": total_apps,
        "ssoConfiguredApplications": len(sso_apps),
        "activeSSOApplications": len(active_sso_apps),
    }

    metadata = {
        "transformationId": "isSSOEnabled",
        "vendor": "JumpCloud",
        "category": "identity-and-access-management",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud application list proves nothing, so the key is returned as None with
# dataCollection.status "error": the check reads Unevaluated, never a pass and never a 0.
def unevaluated(problem, validation):
    return create_response(
        result={"isSSOEnabled": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "isSSOEnabled", "vendor": "JumpCloud",
                  "category": "identity-and-access-management"},
    )


def record_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    return None


def evidence_problem(data):
    items = record_list(data)
    if items is None:
        return "No JumpCloud application list in the response; nothing to evaluate."
    if not all(isinstance(i, dict) for i in items):
        return "The response is not a list of JumpCloud application records."
    return None


def transform(input):
    data, validation = extract_input(input)
    problem = evidence_problem(data)
    if problem:
        return unevaluated(problem, validation)
    return transform_evidence(input)
