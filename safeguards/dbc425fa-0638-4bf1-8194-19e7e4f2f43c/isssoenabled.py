"""
Transformation: isSSOEnabled
Vendor: Google Workspace
Category: Email Security

Evidence: getIdentityProvider, the Admin Settings API feed
GET https://apps-apis.google.com/a/feeds/domain/2.0/{domain}/sso/general, whose returnSpec gives
  idpInfo = entry["apps:property"], a list of {"@name": ..., "@value": ...}, and rawResponse.

Rule (fail closed): true only when the feed is readable AND
  * enableSSO is present and equals "true" (case-insensitive; the string "false" fails), AND
  * samlSignonUri is present and is an https URL (SSO switched on with no identity provider
    sign-in page is not working SSO).
A missing enableSSO in a readable feed fails. A Google error, an empty idpInfo (the returnSpec
default when the feed had no entry), or any other unreadable body is reported as a
data-collection error so Token-Service marks the check unevaluated, never as a pass.

Previously: bool(str(value)) was true for every non-empty string, "false" included, so the check
could not fail (FP-07).

Does not see: SSO profiles created in the newer Cloud Identity inboundSamlSsoProfiles API, or which
org units a profile is assigned to. A tenant that uses only those reads as not enabled here.
"""

import json
from datetime import datetime

CRITERIA_KEY = "isSSOEnabled"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
                "transformationId": CRITERIA_KEY,
                "vendor": "Google Workspace",
                "category": "Email Security"
            }
        }
    }


def vendor_error(data):
    """Google's own error message when the body is an error envelope, else None."""
    if data is None:
        return "No response body"
    if isinstance(data, str) and data.strip() == "":
        return "Empty response body"
    if not isinstance(data, dict):
        return None
    value = data.get("error")
    if value:
        if isinstance(value, dict):
            return str(value.get("message") or value.get("status") or value.get("code") or value)
        return "%s %s" % (value, data.get("message") or data.get("error_description") or "")
    code = data.get("statusCode", data.get("status_code"))
    try:
        if code is not None and int(code) >= 400:
            return "HTTP %s" % code
    except (TypeError, ValueError):
        pass
    return None


def is_true(value):
    """Cloud Identity returns booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def read_properties(data):
    """(dict name -> value, error or None) from idpInfo, rawResponse.entry, or a bare list."""
    props = None
    if isinstance(data, dict):
        if "idpInfo" in data:
            props = data.get("idpInfo")
            if not props and isinstance(data.get("rawResponse"), dict):
                error = vendor_error(data.get("rawResponse"))
                if error is not None:
                    return None, error
        elif isinstance(data.get("rawResponse"), dict):
            raw = data.get("rawResponse")
            error = vendor_error(raw)
            if error is not None:
                return None, error
            entry = raw.get("entry")
            props = entry.get("apps:property") if isinstance(entry, dict) else None
        elif isinstance(data.get("entry"), dict):
            props = data["entry"].get("apps:property")
    elif isinstance(data, list):
        props = data
    if isinstance(props, dict):
        props = [props]
    if not isinstance(props, list) or len(props) == 0:
        return None, "SSO settings feed returned no properties"
    out = {}
    for prop in props:
        if isinstance(prop, dict) and "@name" in prop:
            out[str(prop.get("@name")).strip().lower()] = prop.get("@value")
    if len(out) == 0:
        return None, "SSO settings feed properties could not be read"
    return out, None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if isinstance(data, dict) and "result" in data and isinstance(data.get("result"), (dict, list)):
            data = data["result"]

        error = vendor_error(data)
        props = None
        if error is None:
            props, error = read_properties(data)
        if error is not None:
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                api_errors=[error],
                fail_reasons=["Not measured: " + error],
                recommendations=["Check the Google service account's access to the SSO settings feed and re-evaluate"]
            )

        enabled_raw = props.get("enablesso")
        signon = str(props.get("samlsignonuri") or "").strip()
        enabled = enabled_raw is not None and str(enabled_raw).strip().lower() == "true"
        has_idp = signon.lower().startswith("https://")
        result_value = enabled and has_idp

        idp_host = signon.split("/")[2] if has_idp and len(signon.split("/")) > 2 else ""
        findings = [
            {"metric": "enableSSO", "value": enabled, "reason": "reported %r" % enabled_raw},
            {"metric": "samlSignonUri", "value": has_idp, "reason": idp_host or "not set"},
            {"metric": "ssoWhitelist", "value": True, "reason": "reported %r (not judged)" % props.get("ssowhitelist")},
        ]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("SAML SSO is enabled for the domain with identity provider %s" % idp_host)
        elif enabled_raw is None:
            fail_reasons.append("SSO settings feed did not report enableSSO; SSO not proven")
        elif not enabled:
            fail_reasons.append("SAML SSO is not enabled (enableSSO=%r)" % enabled_raw)
            recommendations.append("Configure SSO with a third-party identity provider in the Admin console")
        else:
            fail_reasons.append("enableSSO is true but no https samlSignonUri is configured")
            recommendations.append("Set the identity provider sign-in page URL in the SSO profile")

        return create_response(
            result={CRITERIA_KEY: result_value},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=findings,
            input_summary={"enableSSO": enabled_raw, "identityProviderHost": idp_host}
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: %s" % str(e)]
        )
