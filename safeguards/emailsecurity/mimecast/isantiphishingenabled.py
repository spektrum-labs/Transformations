"""Transformation: isAntiPhishingEnabled — Mimecast getAccount

Anti-phishing protection is licensed at the account level. The getAccount response
lists active product packages; the presence of any phishing-defense package
(Impersonation Protection [1060], Business Email Compromise [1109], CyberGraph
[1095], or URL Protection (Site) [1043]) confirms anti-phishing email filtering is
active. Packages are matched by their bracketed product-id token so renames don't
break the check.
"""
import json
from datetime import datetime


# Product-id tokens (stable) for Mimecast packages that provide anti-phishing defense.
ANTI_PHISHING_PACKAGE_IDS = {
    "[1060]": "Impersonation Protection",
    "[1109]": "Business Email Compromise",
    "[1095]": "CyberGraph",
    "[1043]": "URL Protection (Site)",
}


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
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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

    # Token-Service navigates into the response's "data" key, so this transform
    # usually receives the bare account list. Re-wrap it (and a lone account dict)
    # so the {meta, data} access below works in the live pipeline and local testing.
    if isinstance(data, list):
        data = {"data": data}
    elif isinstance(data, dict) and "data" not in data and ("packages" in data or "accountCode" in data or "accountName" in data):
        data = {"data": [data]}
    if not isinstance(data, dict):
        data = {}

    account_list = data.get("data") or []
    fail_list = data.get("fail") or []
    meta = data.get("meta") or {}
    meta_status = meta.get("status") if isinstance(meta, dict) else None
    api_errors = [str(f) for f in fail_list] if fail_list else []

    metadata = {
        "transformationId": "isAntiPhishingEnabled",
        "vendor": "Mimecast",
        "category": "Email Security",
    }

    if not account_list:
        return create_response(
            result={"isAntiPhishingEnabled": False, "antiPhishingPackages": []},
            validation=validation,
            fail_reasons=["No account data was returned in the getAccount response. Cannot confirm anti-phishing protection."],
            recommendations=["Verify the API credentials have account read scope and that the account is active."],
            input_summary={"accountCount": 0, "metaStatus": meta_status, "failCount": len(fail_list)},
            api_errors=api_errors,
            metadata=metadata,
        )

    account = account_list[0] if isinstance(account_list[0], dict) else {}
    account_name = account.get("accountName") or ""
    packages = account.get("packages") or []

    found = []
    for pkg in packages:
        pkg_str = str(pkg)
        for token, label in ANTI_PHISHING_PACKAGE_IDS.items():
            if token in pkg_str and label not in found:
                found.append(label)

    is_enabled = len(found) > 0

    if is_enabled:
        pass_reasons = [
            "Mimecast account '" + account_name + "' has anti-phishing protection licensed via: "
            + ", ".join(found) + "."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Mimecast account '" + account_name + "' has no anti-phishing defense packages "
            "(Impersonation Protection, Business Email Compromise, CyberGraph, or URL Protection) in its licensed packages."
        ]
        recommendations = [
            "Enable a Mimecast anti-phishing package (e.g. Impersonation Protection or CyberGraph) to block phishing and impersonation attacks."
        ]

    return create_response(
        result={
            "isAntiPhishingEnabled": is_enabled,
            "antiPhishingPackages": found,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountCount": len(account_list),
            "packageCount": len(packages),
            "antiPhishingPackagesFound": len(found),
            "metaStatus": meta_status,
        },
        api_errors=api_errors,
        metadata=metadata,
    )
