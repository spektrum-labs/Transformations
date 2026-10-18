# confirmedlicensepurchased.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getLicenseInfo -> GET {serverUrl}/V4/License (Accept: application/json)
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         operation GetLicenseInfo: licenseMode (EVALUATION, PRODUCTION, DR_PRODUCTION), edition, expiryDate
#         ("Expiry date of current license in epoch format").
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import datetime
import json


def respond(key, value, reason, extra=None):
    """The full response envelope. dataCollection.status follows the value: None is not measured."""
    result = {key: value}
    if extra:
        for k in extra:
            result[k] = extra[k]
    measured = value is not None
    passed = value is True
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Commvault", "category": "Backups", "schemaVersion": "1.0"},
        },
    }


def transform(input):
    """
    confirmedLicensePurchased = true when licenseMode is PRODUCTION or DR_PRODUCTION and expiryDate, when
    present and non-zero, is in the future. EVALUATION, an expired license or an unreadable body is false.
    """
    key = "confirmedLicensePurchased"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def vendor_error(d):
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    try:
        data = unwrap(parse_input(input), "licenseMode")
        problem = vendor_error(data)
        if problem:
            return respond(key, None, problem)
        mode = str(data.get("licenseMode") or "").upper()
        if not mode:
            return respond(key, None, "Response has no licenseMode")
        if mode not in ("PRODUCTION", "DR_PRODUCTION"):
            return respond(key, False, "License mode is " + mode)
        exp = as_int(data.get("expiryDate"))
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if exp is not None and exp > 0 and exp <= now:
            return respond(key, False, "The " + mode + " license expired (expiryDate " + str(exp) + ")")
        return respond(key, True, mode + " license" + (" valid until epoch " + str(exp) if exp else " with no expiry date"), {"edition": data.get("edition")})
    except Exception as e:
        return respond(key, None, "The transform raised: " + str(e), {"error": str(e)})
