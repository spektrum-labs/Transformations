"""
Transformation: confirmedLicensePurchased
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: EPP
Evaluates: Whether the customer has an active ThreatDown Nebula account with a valid subscription.
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "ThreatDown", "category": "EPP"}
        }
    }


def evaluate(data):
    """Confirm an active ThreatDown licence from GET /nebula/v1/account.

    Real shape: the account object carries product_license_info[], each entry with
    license_status, licensed_seats, license_expires_at, combo_code and
    license_term_type. There is no top-level status/subscription/plan field.
    """
    licenses = data.get("product_license_info") or []
    if not isinstance(licenses, list):
        licenses = []

    now = datetime.utcnow()
    active = []
    seats = 0
    products = []
    expiries = []
    term_types = []

    for lic in licenses:
        if not isinstance(lic, dict):
            continue
        if str(lic.get("license_status", "")).strip().lower() != "active":
            continue

        expires_raw = lic.get("license_expires_at")
        if expires_raw:
            try:
                expires_at = datetime.strptime(str(expires_raw)[:19], "%Y-%m-%dT%H:%M:%S")
                if expires_at < now:
                    continue
                expiries.append(str(expires_raw)[:10])
            except Exception:
                pass

        active.append(lic)

        try:
            seats = seats + int(lic.get("licensed_seats") or 0)
        except Exception:
            pass

        combo = lic.get("combo_code")
        if combo:
            products.append(str(combo))
        term = lic.get("license_term_type")
        if term:
            term_types.append(str(term).lower())

    result = {
        "confirmedLicensePurchased": len(active) > 0,
        "accountName": data.get("name", ""),
        "activeLicenseCount": len(active),
        "licensedSeats": seats,
        "licenseProducts": sorted(set(products)),
        "earliestExpiry": min(expiries) if expiries else "",
    }
    if term_types:
        # Surfaced so not-for-resale / demo tenants are visible rather than silently
        # counted as production coverage.
        result["licenseTermTypes"] = sorted(set(term_types))
    return result


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

        if result_value:
            pass_reasons.append("ThreatDown account is active with a valid subscription")
            if extra_fields.get("accountName"):
                pass_reasons.append(f"Account: {extra_fields['accountName']}")
            if extra_fields.get("licensedSeats"):
                pass_reasons.append(f"Licensed seats: {extra_fields['licensedSeats']}")
            if extra_fields.get("licenseProducts"):
                pass_reasons.append("Products: " + ", ".join(extra_fields["licenseProducts"]))
            if extra_fields.get("licenseTermTypes"):
                pass_reasons.append("Licence term type(s): " + ", ".join(extra_fields["licenseTermTypes"]))
        else:
            fail_reasons.append("No active ThreatDown account or subscription found")
            recommendations.append("Verify ThreatDown Nebula account status and subscription in the admin console")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
