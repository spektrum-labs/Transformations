"""\nTransformation: confirmedLicensePurchased\nVendor: Sophos Renewal  |  Category: sophos-renewal\nEvaluates: Whether the Sophos Central tenant holds at least one active purchased\n(non-trial) license. Inspects the 'licenses' array returned by getLicenses and\nreturns True if at least one entry has a type of 'term', 'ordered', 'enterprise',\nor 'usage'.\n"""
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Sophos Renewal",
                "category": "sophos-renewal"
            }
        }
    }


def evaluate(data):
    """
    Core evaluation logic for confirmedLicensePurchased.

    Inspects the 'licenses' array from the merged getLicenses + getWhoAmI
    response. Returns True when at least one license has a type that indicates
    a real paid purchase: 'term', 'ordered', 'enterprise', or 'usage'.
    Trial-only tenants (type == 'trial') are considered non-compliant.
    """
    PAID_TYPES = ["term", "ordered", "enterprise", "usage"]

    licenses = data.get("licenses", [])
    if not isinstance(licenses, list):
        licenses = []

    total_licenses = len(licenses)
    paid_licenses = []
    trial_licenses = []
    unknown_licenses = []

    for lic in licenses:
        lic_type = ""
        if isinstance(lic, dict):
            lic_type = lic.get("type", "") or ""
        lic_type_lower = lic_type.lower()
        if lic_type_lower in PAID_TYPES:
            paid_licenses.append(lic)
        elif lic_type_lower == "trial":
            trial_licenses.append(lic)
        else:
            unknown_licenses.append(lic)

    has_paid_license = len(paid_licenses) > 0

    paid_summary = []
    for lic in paid_licenses:
        if isinstance(lic, dict):
            entry = lic.get("productName", lic.get("name", "unknown")) + " (" + str(lic.get("type", "")) + ")"
            paid_summary.append(entry)

    return {
        "confirmedLicensePurchased": has_paid_license,
        "totalLicenses": total_licenses,
        "paidLicenseCount": len(paid_licenses),
        "trialLicenseCount": len(trial_licenses),
        "unknownTypeCount": len(unknown_licenses),
        "paidLicenseSummary": paid_summary
    }


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalLicenses", 0)
        paid = eval_result.get("paidLicenseCount", 0)
        trial = eval_result.get("trialLicenseCount", 0)
        paid_names = eval_result.get("paidLicenseSummary", [])

        if result_value:
            pass_reasons.append(
                "At least one paid (non-trial) license is present on this tenant."
            )
            pass_reasons.append(
                "Paid license count: " + str(paid) + " out of " + str(total) + " total licenses."
            )
            for name in paid_names:
                additional_findings.append("Paid license: " + name)
        else:
            fail_reasons.append(
                "No paid licenses found. The tenant has " + str(total) + " license(s), "
                "all of which are trial or unrecognised."
            )
            if trial > 0:
                fail_reasons.append("Trial license count: " + str(trial))
            recommendations.append(
                "Purchase a Sophos Central subscription (Intercept X, MTR, etc.) to replace trial licenses."
            )
            recommendations.append(
                "Ensure the API credential has sufficient permissions to read license data."
            )

        if total == 0:
            fail_reasons.append("The licenses array returned by the API was empty.")
            recommendations.append(
                "Verify that the Tenant ID and Data Region URL are correct and that the "
                "API credential has the 'Service Principal Read-Only' role."
            )

        input_summary = {
            "totalLicenses": total,
            "paidLicenseCount": paid,
            "trialLicenseCount": trial,
            "confirmedLicensePurchased": result_value
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
