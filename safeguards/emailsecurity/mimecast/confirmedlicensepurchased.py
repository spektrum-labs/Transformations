"""
Transformation: confirmedLicensePurchased
Vendor: Mimecast
Category: Email Security / Licensing

Evaluates if a valid Mimecast subscription is active by checking the
account information endpoint for packages and account details.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Mimecast",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

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

        license_purchased = False
        additional_findings = []
        account_name = ""
        account_code = ""
        package_count = 0

        account = None
        if isinstance(data, list) and len(data) > 0:
            account = data[0] if isinstance(data[0], dict) else None
        elif isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                account = data["data"][0] if isinstance(data["data"][0], dict) else None
            else:
                account = data

        if isinstance(account, dict):
            account_name = account.get("accountName", "")
            account_code = account.get("accountCode", "")
            packages = account.get("packages", [])
            if isinstance(packages, list):
                package_count = len(packages)

            license_purchased = package_count > 0

            if license_purchased:
                for pkg in packages:
                    if isinstance(pkg, str):
                        additional_findings.append(f"Package: {pkg}")

        if license_purchased:
            pass_reasons.append(
                f"Mimecast license confirmed for {account_name} ({account_code}) "
                f"with {package_count} {'package' if package_count == 1 else 'packages'}"
            )
        else:
            fail_reasons.append("No Mimecast packages found - license not confirmed")
            recommendations.append("Ensure a valid Mimecast subscription is active with licensed packages")

        return create_response(
            result={
                criteriaKey: license_purchased,
                "packageCount": package_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "accountName": account_name,
                "accountCode": account_code,
                "packageCount": package_count
            },
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
