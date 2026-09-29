"""
Transformation: isSSOEnabled
Vendor: AWS Security Hub  |  Category: Cloud Security

Workflow getSSOFederation (two steps, each under its own output key):
  samlProviders <- getSAMLProviders: IAM ListSAMLProviders (Query API, XML parsed by Integration-Service)
      https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListSAMLProviders.html
  ssoInstances  <- listSSOInstances: sso-admin ListInstances (awsJson1_1)
      https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListInstances.html

isSSOEnabled is true when the account federates sign-in: at least one IAM SAML identity provider OR an
ACTIVE IAM Identity Center instance. It is false only when BOTH were read and both are empty. Anything
else (a leg missing, an error body, an unrecognised shape) is null with dataCollection status "error":
a read that failed is not a control that is off.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isSSOEnabled"
TRANSFORM_ID = "isssoenabled"


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def find_legs(data):
    for depth in range(5):
        if not isinstance(data, dict):
            return None
        if "samlProviders" in data or "ssoInstances" in data:
            return data
        nxt = None
        for key in ("data", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), dict):
                nxt = data[key]
                break
        if nxt is None:
            return None
        data = nxt
    return None


def leg_error(leg):
    if leg is None:
        return "not returned"
    if not isinstance(leg, dict):
        return "not an object"
    if leg.get("error") is True:
        return "Integration-Service error: " + str(leg.get("message") or leg.get("errorMessage") or "")[:200]
    if leg.get("__type"):
        return "AWS error " + str(leg.get("__type"))
    if isinstance(leg.get("ErrorResponse"), dict):
        err = leg["ErrorResponse"].get("Error") or {}
        return "AWS error " + str(err.get("Code") if isinstance(err, dict) else err)
    return None


def saml_provider_count(leg):
    resp = leg.get("ListSAMLProvidersResponse")
    if not isinstance(resp, dict):
        return None
    result = resp.get("ListSAMLProvidersResult")
    if not isinstance(result, dict) or "SAMLProviderList" not in result:
        return None
    plist = result.get("SAMLProviderList")
    if plist is None or plist == "":
        return 0
    if not isinstance(plist, dict):
        return None
    member = plist.get("member")
    if member is None:
        return 0
    if isinstance(member, dict):
        member = [member]
    if not isinstance(member, list):
        return None
    return len([m for m in member if isinstance(m, dict) and m.get("Arn")])


def active_instance_count(leg):
    instances = leg.get("Instances")
    if not isinstance(instances, list):
        return None
    if leg.get("NextToken"):
        return None
    return len([i for i in instances if isinstance(i, dict) and i.get("Status") == "ACTIVE"])


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (errors or []) else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (errors or []) else "success", "errors": errors or [],
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORM_ID, "vendor": "AWS Security Hub", "category": "Cloud Security"},
        },
    }


def transform(input):
    try:
        legs = find_legs(parse(input))
        if legs is None:
            return build_response({CRITERIA_KEY: None}, errors=["Neither SAML providers nor IAM Identity Center instances were returned"])
        saml, sso, problems = None, None, []
        err = leg_error(legs.get("samlProviders"))
        if err is None:
            saml = saml_provider_count(legs["samlProviders"])
            if saml is None:
                problems.append("IAM ListSAMLProviders: unrecognised response shape")
        else:
            problems.append("IAM ListSAMLProviders: " + err)
        err = leg_error(legs.get("ssoInstances"))
        if err is None:
            sso = active_instance_count(legs["ssoInstances"])
            if sso is None:
                problems.append("sso-admin ListInstances: unrecognised response shape or a page left unread")
        else:
            problems.append("sso-admin ListInstances: " + err)
        summary = {"samlProviderCount": saml, "activeIdentityCenterInstanceCount": sso}
        result = {CRITERIA_KEY: None, "samlProviderCount": saml, "activeIdentityCenterInstanceCount": sso}
        if (saml or 0) > 0 or (sso or 0) > 0:
            result[CRITERIA_KEY] = True
            reasons = []
            if (saml or 0) > 0:
                reasons.append(str(saml) + " IAM SAML identity provider(s)")
            if (sso or 0) > 0:
                reasons.append(str(sso) + " ACTIVE IAM Identity Center instance(s)")
            return build_response(result, pass_reasons=["Federated sign-in configured: " + "; ".join(reasons)], summary=summary)
        if saml == 0 and sso == 0:
            result[CRITERIA_KEY] = False
            return build_response(result, fail_reasons=["No IAM SAML identity provider and no ACTIVE IAM Identity Center instance"],
                                  summary=summary)
        return build_response(result, errors=problems, summary=summary)
    except Exception as error:
        return build_response({CRITERIA_KEY: None}, errors=[str(error)])
