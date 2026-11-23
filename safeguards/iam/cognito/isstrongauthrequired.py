"""
Transformation: isStrongAuthRequired
Vendor: Amazon Cognito (user pools)  |  Category: Identity and Access Management

CLAIM. The Cognito user pool requires a second factor from every user the pool signs in itself.

SOURCE. One read, GetUserPoolMfaConfig (IAM permission cognito-idp:GetUserPoolMfaConfig):
  POST https://cognito-idp.<region>.amazonaws.com/
  X-Amz-Target: AWSCognitoIdentityProviderService.GetUserPoolMfaConfig
  Content-Type: application/x-amz-json-1.1, signed with SigV4 (service cognito-idp)
  body {"UserPoolId": "<region>_<id>"}
  -> {"MfaConfiguration": "OFF" | "ON" | "OPTIONAL",
      "SoftwareTokenMfaConfiguration": {"Enabled": bool},
      "SmsMfaConfiguration": {"SmsAuthenticationMessage": str, "SmsConfiguration": {...}},
      "EmailMfaConfiguration": {"Message": str, "Subject": str},
      "WebAuthnConfiguration": {"RelyingPartyId": str, "UserVerification": str, ...}}
  AWS API reference, GetUserPoolMfaConfig: "When ON, all users must set up MFA before they can
  sign in. When OPTIONAL, your application must make a client-side determination of whether a
  user wants to register an MFA device." Developer guide, "Adding MFA to a user pool": with MFA
  required, password sign-in is always followed by an MFA challenge, and one-time-password
  first factors cannot be enabled in the same pool.

RULE. ON is True. OFF is False (no second factor is offered). OPTIONAL is False: the pool does
not require it, so a user who never set one up signs in without one (adaptive authentication
needs OPTIONAL, so a pool that relies on it is not "required for every user" either).
Scope: the users Cognito itself authenticates. Federated users are authenticated by their own
identity provider, which this read says nothing about.

FAIL CLOSED (None, dataCollection "error", never a pass or a fail): an empty body; an AWS or
Integration-Service error (AccessDenied, ResourceNotFound, an unsigned or unknown-operation
reply, an HTTP error status); no MfaConfiguration; any MfaConfiguration other than ON, OFF or
OPTIONAL; any exception.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isStrongAuthRequired"
TRANSFORM_ID = "isstrongauthrequired"
VENDOR = "Amazon Cognito"
WRAPPERS = ["api_response", "response", "result", "apiResponse"]
MODES = ("ON", "OFF", "OPTIONAL")


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"),
                           "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success",
                               "errors": transform_err_list, "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": TRANSFORM_ID, "vendor": VENDOR,
                         "category": "Identity and Access Management"},
        },
    }


def not_evaluated(reason, summary=None):
    return create_response(result={CRITERIA_KEY: None}, api_errors=[reason],
                           fail_reasons=["Not evaluated: " + reason], input_summary=summary or {})


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.startswith("<"):
            raise ValueError("HTML or XML body; expected JSON from the vendor API")
        return json.loads(text)
    return value


def unwrap(data):
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = data["data"]
    for depth in range(4):
        if not isinstance(data, dict) or "MfaConfiguration" in data:
            break
        moved = False
        for key in WRAPPERS:
            if isinstance(data.get(key), (dict, list)):
                data = data[key]
                moved = True
                break
        if not moved:
            break
    return data


def error_reason(data):
    """A reason when the body is an AWS or Integration-Service error, else None."""
    if not isinstance(data, dict):
        return None
    if data.get("error") is True:
        return "Integration-Service returned an error: " + str(data.get("message") or "")[:200]
    if data.get("__type"):
        name = str(data.get("__type")).split("#")[-1]
        return "AWS error " + name[:80] + ": " + str(data.get("message") or data.get("Message") or "")[:160]
    out = data.get("Output")
    if isinstance(out, dict) and out.get("__type"):
        return ("AWS error " + str(out.get("__type")).split("#")[-1][:80]
                + " (the request was not dispatched; Content-Type must be application/x-amz-json-1.1)")
    if data.get("success") is False:
        return "vendor reported success=false: " + str(data.get("message") or data.get("Message") or "")[:200]
    if isinstance(data.get("error"), (dict, str)) and data.get("error"):
        return "error body: " + json.dumps(data.get("error"))[:200]
    for key in ("statusCode", "status_code", "httpStatus"):
        code = data.get(key)
        if isinstance(code, int) and code >= 400:
            return "HTTP " + str(code)
    return None


def configured_factors(data):
    """Which second factors the pool configures (information only; the verdict is MfaConfiguration)."""
    factors = []
    totp = data.get("SoftwareTokenMfaConfiguration")
    if isinstance(totp, dict) and totp.get("Enabled") is True:
        factors.append("TOTP")
    sms = data.get("SmsMfaConfiguration")
    if isinstance(sms, dict) and isinstance(sms.get("SmsConfiguration"), dict) and sms.get("SmsConfiguration"):
        factors.append("SMS")
    email = data.get("EmailMfaConfiguration")
    if isinstance(email, dict) and email:
        factors.append("EMAIL")
    return factors


def transform(input):
    try:
        data = unwrap(parse(input))
        if data is None or data == {} or data == []:
            return not_evaluated("empty response: the user pool MFA configuration was not read")
        reason = error_reason(data)
        if reason:
            return not_evaluated(reason)
        if not isinstance(data, dict) or "MfaConfiguration" not in data:
            return not_evaluated("no MfaConfiguration in the response")
        mode = data.get("MfaConfiguration")
        if mode not in MODES:
            return not_evaluated("MfaConfiguration is not one of ON, OFF or OPTIONAL")
        factors = configured_factors(data)
        summary = {"mfaConfiguration": mode, "factorsConfigured": factors}
        result = {CRITERIA_KEY: mode == "ON", "mfaConfiguration": mode, "factorsConfigured": factors}
        if mode == "ON":
            return create_response(
                result=result, input_summary=summary,
                pass_reasons=["The user pool's MFA setting is ON: every user Cognito signs in must set up a "
                              "second factor before signing in. Users who sign in through a federated identity "
                              "provider are authenticated by that provider, not by Cognito."])
        if mode == "OPTIONAL":
            return create_response(
                result=result, input_summary=summary,
                fail_reasons=["The user pool's MFA setting is OPTIONAL: a user who has not set up a second factor "
                              "signs in without one."],
                recommendations=["Set the user pool's MFA to Required. Adaptive authentication (threat protection) "
                                 "needs MFA set to Optional, so a pool that relies on it must enforce MFA another way."])
        return create_response(
            result=result, input_summary=summary,
            fail_reasons=["The user pool's MFA setting is OFF: users cannot register a second factor."],
            recommendations=["Turn on MFA for the user pool and set it to Required."])
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
