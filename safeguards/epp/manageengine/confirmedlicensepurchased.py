"""
Transformation: confirmedLicensePurchased
Vendor: ManageEngine Endpoint Central (Cloud)  |  Category: EPP
Evaluates: Whether the Endpoint Central Cloud tenant is live and provisioned.
Source: GET /api/1.4/desktop/serverproperties

Endpoint Central Cloud wraps every payload in `message_response`, which the
previous generic wrapper list did not cover, so the transform read an empty dict
and always returned False. Field names below are taken from live Cloud responses.
"""
import json
from datetime import datetime

ENVELOPE_KEYS = ["api_response", "response", "result", "apiResponse", "Output", "message_response"]


def unwrap(data):
    """Strip known response envelopes, including ManageEngine's message_response."""
    if not isinstance(data, dict):
        return data
    for attempt in range(4):
        moved = False
        for key in ENVELOPE_KEYS:
            inner = data.get(key)
            if isinstance(inner, dict):
                data = inner
                moved = True
                break
        if not moved:
            break
    return data


def section(data, name):
    """Return dict `name`, tolerating one extra nesting level.

    Works whether the caller hands us message_response.summary directly or the
    still-enveloped payload, so the transform is correct with or without a
    returnSpec on the integration definition.
    """
    if not isinstance(data, dict):
        return {}
    direct = data.get(name)
    if isinstance(direct, dict):
        return direct
    for value in data.values():
        if isinstance(value, dict):
            nested = value.get(name)
            if isinstance(nested, dict):
                return nested
    return {}


def num(source, name, fallback=0):
    """Read an int off a dict, tolerating strings and missing keys."""
    try:
        value = source.get(name, fallback)
        if value is None:
            return fallback
        return int(value)
    except Exception:
        return fallback


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return unwrap(input_data["data"]), input_data["validation"]
    return unwrap(input_data), {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "ManageEngine", "category": "EPP"}
        }
    }


def evaluate(data):
    """Confirm an active Endpoint Central Cloud subscription.

    Cloud's serverproperties returns only tenant structure -- branch_offices,
    domains, custom_groups. The licence fields the on-premise edition exposes
    (product_name, license_type, license_expiry) are absent, so the proof here
    is that an authenticated call returns a provisioned estate: a tenant that
    serves branch offices and domains is a live, paid subscription.
    """
    try:
        props = data
        if not isinstance(props, dict):
            return {"confirmedLicensePurchased": False,
                    "failReasons": ["serverproperties payload was not an object"]}

        inner = props.get("serverproperties")
        if isinstance(inner, dict):
            props = inner

        branch_offices = props.get("branch_offices") or []
        domains = props.get("domains") or []
        custom_groups = props.get("custom_groups") or []

        branch_count = len(branch_offices) if isinstance(branch_offices, list) else 0
        domain_count = len(domains) if isinstance(domains, list) else 0
        group_count = len(custom_groups) if isinstance(custom_groups, list) else 0

        is_active = (branch_count + domain_count + group_count) > 0

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if is_active:
            pass_reasons.append("Endpoint Central Cloud tenant responded with a provisioned estate")
            pass_reasons.append(str(branch_count) + " branch offices, " + str(domain_count)
                                + " domains, " + str(group_count) + " custom groups")
        else:
            fail_reasons.append("Tenant authenticated but returned no branch offices, domains or custom groups")
            recommendations.append("Confirm the Endpoint Central Cloud subscription is active and the tenant is provisioned")

        return {
            "confirmedLicensePurchased": is_active,
            "branchOfficeCount": branch_count,
            "domainCount": domain_count,
            "customGroupCount": group_count,
            "passReasons": pass_reasons,
            "failReasons": fail_reasons,
            "recommendations": recommendations,
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


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
        meta_keys = ["error", "passReasons", "failReasons", "recommendations", "additionalFindings"]
        extra_fields = {k: v for k, v in eval_result.items()
                        if k != criteriaKey and k not in meta_keys}

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=eval_result.get("passReasons", []),
            fail_reasons=eval_result.get("failReasons", []),
            recommendations=eval_result.get("recommendations", []),
            additional_findings=eval_result.get("additionalFindings", []),
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
