
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


def transform(input_data):
    """
    Transformation: isEmailLoggingEnabled (Mimecast)

    Also emitted as isEmailSecurityLoggingEnabled (same value, same evidence).

    Checks whether the Mimecast account has the Enhanced Logging package
    (product ID 1061) active. Enhanced Logging is Mimecast's MTA-level
    log stream used for SIEM integration. Its presence in the account
    packages list confirms the feature is licensed and enabled.
    """
    if isinstance(input_data, bytes):
        input_data = input_data.decode("utf-8")
    if isinstance(input_data, str):
        try:
            input_data = json.loads(input_data) if input_data.strip() else None
        except ValueError:
            input_data = None
    data, validation = extract_input(input_data)

    # An Integration-Service error envelope ({"error": true, "message": "... HTTP 403 ..."}) or a
    # Mimecast "fail" list is not an account without Enhanced Logging: report it as not measured
    # (dataCollection error, shown Unevaluated) instead of a FAIL.
    api_errors = []
    if data is None:
        api_errors.append("No response body from getAccount")
    elif isinstance(data, dict):
        if data.get("error") is True or str(data.get("status", "")).lower() == "error":
            api_errors.append("getAccount failed: %s" % str(data.get("message") or "Integration error")[:300])
        fails = data.get("fail")
        if isinstance(fails, list) and fails and not data.get("data"):
            api_errors.append("Mimecast returned fail: %s" % json.dumps(fails)[:300])
    if api_errors:
        return create_response(
            result={"isEmailLoggingEnabled": False, "isEmailSecurityLoggingEnabled": False},
            validation=validation,
            fail_reasons=["Not measured: " + "; ".join(api_errors)],
            api_errors=api_errors,
            metadata={"transformationId": "isEmailLoggingEnabled", "vendor": "Mimecast", "category": "emailsecurity"},
        )

    # Token-Service navigates into the response's "data" key, so this transform
    # usually receives the bare account list. Re-wrap it (and a lone account dict)
    # so the {meta, data} access below works in the live pipeline and local testing.
    if isinstance(data, list):
        data = {"data": data}
    elif isinstance(data, dict) and "data" not in data and ("packages" in data or "accountCode" in data or "accountName" in data):
        data = {"data": [data]}
    if not isinstance(data, dict):
        data = {}

    # getAccount returns {"data": [...], "fail": [], "meta": {...}}
    account_list = data.get("data") or []
    account = account_list[0] if account_list else {}

    packages = account.get("packages") or []
    account_code = account.get("accountCode") or "unknown"
    account_name = account.get("accountName") or "unknown"

    # Enhanced Logging package string as returned by the API
    ENHANCED_LOGGING_PACKAGE = "Enhanced Logging [1061]"

    enhanced_logging_enabled = any(
        ENHANCED_LOGGING_PACKAGE in pkg for pkg in packages
    )

    total_packages = len(packages)

    if enhanced_logging_enabled:
        pass_reasons = [
            f"Account '{account_name}' ({account_code}) has the '{ENHANCED_LOGGING_PACKAGE}' "
            f"package active in its licensed packages list ({total_packages} total packages). "
            "Enhanced Logging enables MTA-level SIEM log streaming, confirming email security "
            "logs are integrated with SIEM."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Account '{account_name}' ({account_code}) does not have the "
            f"'{ENHANCED_LOGGING_PACKAGE}' package in its licensed packages list "
            f"({total_packages} packages found). Enhanced Logging must be active for "
            "email security logs to be streamed to a SIEM."
        ]
        recommendations = [
            "Enable Enhanced Logging under Account Settings in the Mimecast Administration Console "
            "and configure a SIEM connector to receive MTA log data. Contact your Mimecast "
            "account representative if the Enhanced Logging package is not included in your subscription."
        ]

    return create_response(
        result={
            "isEmailLoggingEnabled": enhanced_logging_enabled,
            # Same evidence under the key the Email Security requirement asks for; Token-Service
            # reads transformedResponse[criteriaKey] exactly, so a synonym evaluates nothing.
            "isEmailSecurityLoggingEnabled": enhanced_logging_enabled,
            "enhancedLoggingPackageFound": enhanced_logging_enabled,
            "totalPackages": total_packages,
            "accountCode": account_code,
            "accountName": account_name,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "accountCode": account_code,
            "accountName": account_name,
            "totalPackages": total_packages,
            "enhancedLoggingPackageFound": enhanced_logging_enabled,
        },
        metadata={
            "transformationId": "isEmailLoggingEnabled",
            "vendor": "Mimecast",
            "category": "emailsecurity",
        },
    )
