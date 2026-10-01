"""Transformation: isAttachmentSandboxDetonationEnabled - Mimecast Email Security Cloud Integrated, method getAccount.

POST /api/account/get-account lists the account's licensed product packages. True when a package that
provides Attachment Protection (sandbox detonation of attachments) is licensed, matched by its bracketed product id ([1056], [1059]). False when getAccount
returns the account and its package list without one. None when the body is an error, a fail entry,
an auth envelope, unrelated JSON, or an account with no package list.

This proves the package is licensed on the account, not how its policies are tuned.
"""
import json
from datetime import datetime


KEY = "isAttachmentSandboxDetonationEnabled"
PACKAGES = {"[1056]": "Attachment Protection (Site)", "[1059]": "Attachment Protection (Pro)"}


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
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


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled getAccount body in a {data, validation}
    # envelope, so meta and fail stay visible.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def find_account(obj):
    """(account, error) for the first account in a Mimecast getAccount body."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        fail = cur.get("fail")
        if isinstance(fail, list) and fail:
            return None, json.dumps(fail)[:300]
        if cur.get("error") is True or cur.get("errors"):
            return None, json.dumps(cur.get("errors") or cur.get("message") or "error")[:300]
        meta = cur.get("meta")
        status = meta.get("status") if isinstance(meta, dict) else None
        if isinstance(status, int) and not isinstance(status, bool) and status != 200:
            return None, "meta.status " + str(status)
        accounts = cur.get("data")
        if isinstance(accounts, list):
            if accounts and isinstance(accounts[0], dict) and isinstance(accounts[0].get("packages"), list):
                return accounts[0], None
            return None, None
        nxt = None
        for key in ["apiResponse", "result", "response", "api_response", "Output", "data"]:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def not_measured(problem, validation):
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": KEY, "vendor": "Mimecast", "category": "Email Security"},
    )


def transform(input):
    validation = extract_validation(input)
    account, error = find_account(raw_body(input))
    if error is not None:
        return not_measured("Mimecast getAccount returned an error: " + error, validation)
    if account is None:
        return not_measured("No Mimecast account with a package list in the response; nothing to evaluate.", validation)
    packages = [str(p) for p in account.get("packages")]
    found = []
    for pkg in packages:
        for token in PACKAGES:
            if token in pkg and PACKAGES[token] not in found:
                found.append(PACKAGES[token])
    enabled = len(found) > 0
    if enabled:
        text = "Licensed: " + ", ".join(found) + " (" + str(len(packages)) + " packages on the account)."
    else:
        text = "None of " + ", ".join(PACKAGES[t] for t in PACKAGES) + " is among the account's " + str(len(packages)) + " licensed packages."
    return create_response(
        result={KEY: enabled, "matchedPackages": found, "licensedPackageCount": len(packages)},
        validation=validation,
        pass_reasons=[text] if enabled else [],
        fail_reasons=[] if enabled else [text],
        recommendations=[] if enabled else ["License and enable " + "Attachment Protection (sandbox detonation of attachments)" + " in Mimecast."],
        input_summary={"licensedPackageCount": len(packages), "matched": len(found)},
        metadata={"transformationId": KEY, "vendor": "Mimecast", "category": "Email Security"},
    )
