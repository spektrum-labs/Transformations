"""
Transformation: confirmedLicensePurchased
Vendor: Huntress SAT (Curricula)
Category: Training / Licensing

Confirms the customer's Huntress SAT (Curricula) account is active and on a
valid paid plan. Consumes /api/v1/accounts/{accountId} which returns a single
JSON:API account record:

  {"data": {"type": "accounts", "id": "...", "attributes": {name, status, type, plan, licenses, ...}}}

Token-Service preprocesses the wrapper so the transformation receives either the
full envelope or the inner record directly. Both shapes are handled.
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
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Huntress SAT",
                "category": "Training"
            }
        }
    }


def pull_account_attributes(data):
    """JSON:API account record can arrive as the envelope, the inner record, or
    the bare attributes block depending on how Token-Service preprocesses it."""
    if isinstance(data, dict):
        if isinstance(data.get('data'), dict):
            inner = data['data']
            if isinstance(inner.get('attributes'), dict):
                return inner['attributes']
            return inner
        if isinstance(data.get('attributes'), dict):
            return data['attributes']
        return data
    return {}


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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        attrs = pull_account_attributes(data)

        status = str(attrs.get('status', '')).lower()
        plan = str(attrs.get('plan', '')).strip()
        account_type = str(attrs.get('type', '')).strip()
        name = str(attrs.get('name', '')).strip()

        # A confirmed license = active status AND a non-empty plan that isn't trial-only.
        # type=="Sandbox" identifies sandbox accounts (not real paid licenses).
        is_active = status == 'active'
        is_paid = account_type.lower() in ('paid', '') and account_type.lower() != 'sandbox'
        has_plan = bool(plan)

        license_purchased = is_active and is_paid and has_plan

        if license_purchased:
            pass_reasons.append(
                f"Huntress SAT subscription confirmed: account '{name or 'unknown'}' "
                f"is {status} on the {plan} plan"
            )
        else:
            reason_parts = []
            if not is_active:
                reason_parts.append(f"account status is '{status or 'unknown'}'")
            if not has_plan:
                reason_parts.append("no plan field present")
            if account_type.lower() == 'sandbox':
                reason_parts.append("account type is 'Sandbox' (not a paid license)")
            fail_reasons.append(
                "Huntress SAT subscription is not active: " + ", ".join(reason_parts)
                if reason_parts else "Huntress SAT subscription could not be confirmed"
            )
            recommendations.append(
                "Verify the customer's Huntress Managed SAT subscription is active and on a paid plan"
            )

        return create_response(
            result={
                criteriaKey: license_purchased,
                "accountName": name or None,
                "accountStatus": status or None,
                "accountType": account_type or None,
                "plan": plan or None
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "accountStatus": status or None,
                "accountType": account_type or None,
                "plan": plan or None
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
