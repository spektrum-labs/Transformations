"""
Transformation: isSSOEnabled
Vendor: NinjaOne
Category: Identity / Authentication
Method: getTechnicians (GET /v2/user/technicians)

True when EVERY active NinjaOne technician signs in through single sign-on. Technicians are the
administrators of the tool, so one technician on a native NinjaOne password is an administrator
account outside the identity provider, and the control fails. NinjaOne
exposes no tenant-level SSO or identity-provider setting; the evidence it does publish is the
per-technician `authType` field (NinjaOne Public API 2.0, Technician schema: "Native or SSO
authentication"; https://app.ninjarmm.com/apidocs/NinjaRMM-API-v2.json, operationId
getTechnicians). The endpoint takes no paging parameters and returns the whole list.

Population: technicians with `enabled` not false and, where reported, `invitationStatus`
REGISTERED. A pending or expired invitation is not someone signing in.

This file used to answer `data.get('isSSOEnabled', affirmative_signal(data))`. No NinjaOne API
returns a field of that name, so the verdict was always the fallback, which is True for any
non-empty collection -- "the API returned some records" reported as "SSO is enabled". A body
that is not a technician list (a device list, an empty or error body) proves nothing about
sign-in and now reads None with a dataCollection error: Unevaluated, never True or False.
"""

import json
from datetime import datetime

KEY = "isSSOEnabled"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
                "transformationId": "isIDPEnabled",
                "vendor": "NinjaOne",
                "category": "Identity"
            }
        }
    }


def vendor_error(data):
    """Why `data` is a NinjaOne or platform error envelope, or None."""
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "NinjaOne returned HTTP " + str(code)
    result_code = data.get("resultCode")
    if isinstance(result_code, str) and result_code.strip().upper() not in ("", "SUCCESS"):
        return "NinjaOne returned resultCode " + result_code.strip()[:60]
    for name in ("errorMessage", "error", "errors", "error_description"):
        if data.get(name):
            return "NinjaOne returned an error: " + str(data.get(name))[:200]
    return None


def technician_records(data):
    """The list of records in the body, wherever the engine put it, or None."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for name in ("technicians", "items", "results", "value", "data"):
            if isinstance(data.get(name), list):
                return data[name]
    return None


def is_active(record):
    if record.get("enabled") is False:
        return False
    status = record.get("invitationStatus")
    if isinstance(status, str) and status.strip().upper() != "REGISTERED":
        return False
    user_type = record.get("userType")
    if isinstance(user_type, str) and user_type.strip().upper() != "TECHNICIAN":
        return False
    return True


def measure(data):
    """(value, summary, problem). value is None, with a problem, when nothing was measured."""
    if not isinstance(data, (dict, list)) or not data:
        return None, {}, "NinjaOne returned no body: nothing was measured"
    problem = vendor_error(data)
    if problem:
        return None, {}, problem
    records = technician_records(data)
    if not records:
        return None, {}, ("The response carries no technician list (GET /v2/user/technicians): "
                          "nothing about sign-in was measured")
    described = []
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("authType"), str):
            described.append(record)
    if not described:
        return None, {}, ("No record carries authType, so this is not a technician list (a device "
                          "list cannot evidence SSO): nothing was measured")
    active = []
    # The `described` check above only guards "is this a technician list at all". Every active
    # record counts toward "all on SSO", including one whose authType is missing, null or not a
    # string: it cannot be confirmed as SSO, so it lands in `other` (not measured), never skipped.
    for record in records:
        if isinstance(record, dict) and is_active(record):
            active.append(record)
    sso = 0
    native = 0
    other = 0
    for record in active:
        raw = record.get("authType")
        auth_type = raw.strip().upper() if isinstance(raw, str) else ""
        if auth_type == "SSO":
            sso = sso + 1
        elif auth_type == "NATIVE":
            native = native + 1
        else:
            other = other + 1
    summary = {"technicianRecords": len(records), "activeTechnicians": len(active),
               "ssoTechnicians": sso, "nativeTechnicians": native, "otherAuthType": other}
    if not active:
        return None, summary, ("No enabled, registered technician in the list: nothing about "
                               "sign-in was measured")
    # Every technician is an administrator of the tool, so the rule is "all of them on SSO".
    # A technician known to sign in natively fails it outright, whatever else is in the list.
    if native:
        return False, summary, None
    # No native technician, but some carry an authType this code does not recognise. "All on
    # SSO" cannot be confirmed: the enum spelling comes from the spec and has never been checked
    # against a captured body, so an unseen value (a new IdP type, a different case or spelling)
    # could be either. Not measured, rather than a confident answer in either direction.
    if other:
        return None, summary, (str(other) + " active technician(s) carry an authType this check does "
                               "not recognise, so sign-in was not measured")
    return True, summary, None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            value, summary, problem = None, {}, "Input validation failed: nothing was measured"
        else:
            value, summary, problem = measure(data)

        # measured = value is not None: the failure channel is derived from the value, so no
        # branch can return an unmeasured answer under a "success" status.
        if value is None:
            reason = problem or "Nothing was measured"
            return create_response(
                result={KEY: None},
                validation=validation,
                fail_reasons=[reason],
                api_errors=[reason],
                input_summary=summary
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if value:
            pass_reasons.append("All %d active technicians sign in through SSO"
                                % summary["activeTechnicians"])
        else:
            fail_reasons.append("%d of %d active technicians sign in with a native NinjaOne password, "
                                "not SSO" % (summary["nativeTechnicians"], summary["activeTechnicians"]))
            recommendations.append("Move every NinjaOne technician to the identity provider; technicians "
                                   "administer the tool, so none should sign in natively")

        return create_response(
            result={KEY: value},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={KEY: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)],
            api_errors=["Transformation error: nothing was measured"]
        )
