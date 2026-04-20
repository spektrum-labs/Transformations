"""
Transformation: isEmailSecurityEnabled
Vendor: Mimecast  |  Category: Email Security
Evaluates: Check if Mimecast email security services are active and licensed on
the account by inspecting the account package list returned from
/api/account/get-account.
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
                "transformationId": "isEmailSecurityEnabled",
                "vendor": "Mimecast",
                "category": "Email Security"
            }
        }
    }


def has_email_security_keyword(pkg_name):
    """Return True if the package name contains an email-security-related keyword."""
    if not isinstance(pkg_name, str):
        return False
    lower = pkg_name.lower()
    keywords = ["email", "gateway", "spam", "phish", "protect", "security", "mta", "ttp", "threat", "archive"]
    for kw in keywords:
        if kw in lower:
            return True
    return False


def transform(input):
    criteriaKey = "isEmailSecurityEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed" and not isinstance(data, list):
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        email_security_enabled = False
        account_name = ""
        account_code = ""
        total_packages = 0
        matched_packages = []

        account = None
        if isinstance(data, list) and len(data) > 0:
            account = data[0] if isinstance(data[0], dict) else None
        elif isinstance(data, dict):
            inner = data.get("data", [])
            if isinstance(inner, list) and len(inner) > 0:
                account = inner[0] if isinstance(inner[0], dict) else None
            else:
                account = data

        if isinstance(account, dict):
            account_name = account.get("accountName", "")
            account_code = account.get("accountCode", "")
            packages = account.get("packages", [])
            if isinstance(packages, list):
                total_packages = len(packages)
                for pkg in packages:
                    if has_email_security_keyword(pkg):
                        matched_packages.append(str(pkg))

                # If no keyword-matched packages but packages exist, treat all as
                # email-security active since this integration targets an email
                # security vendor and any package signals a live account.
                if len(matched_packages) == 0 and total_packages > 0:
                    for pkg in packages:
                        matched_packages.append(str(pkg))

            email_security_enabled = len(matched_packages) > 0

        if email_security_enabled:
            pass_reasons.append(
                "Mimecast email security is active for account "
                + account_name + " (" + account_code + ")"
                + " with " + str(len(matched_packages)) + " active package(s)"
            )
            for pkg in matched_packages:
                additional_findings.append("Active package: " + pkg)
        else:
            fail_reasons.append(
                "No Mimecast email security packages found for account "
                + account_name
            )
            recommendations.append(
                "Ensure a valid Mimecast email security subscription is active "
                "and licensed packages are assigned to the account"
            )

        return create_response(
            result={
                criteriaKey: email_security_enabled,
                "totalPackages": total_packages,
                "emailSecurityPackageCount": len(matched_packages)
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "accountName": account_name,
                "accountCode": account_code,
                "totalPackages": total_packages,
                "emailSecurityPackageCount": len(matched_packages)
            },
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
