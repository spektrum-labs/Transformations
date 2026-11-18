"""
Transformation: confirmedLicensePurchased
Vendor: Duo  |  Category: iam
Evaluates: the paid Duo edition the account reports, from GET /admin/v1/info/summary
("Grant read information" Admin API permission).

Duo documents the summary's "edition" field as "Current edition (including trials) of the account",
for example "Duo Premier". Verdict:
  * a paid edition (Essentials, Advantage, Premier, or the legacy MFA, Access, Beyond and Federal names,
    or the edition codes ENTERPRISE, PLATFORM, BEYOND) -> True, with a pass reason that says the edition is
    "as reported by Duo (Duo includes trials)": the edition string is the only evidence Duo gives;
  * an edition string that contains "trial", or Duo Free (code PERSONAL) -> False: no purchased licence;
  * Duo's 403 / 40301 refusal -> None, the customer grants "Grant read information"
    (errorCode scope_not_granted with requiredScope); a 401 -> None, the customer reconnects;
  * a summary with no edition field -> None, coded NOT-AVAILABLE;
  * an edition this check does not know, an error body or unreadable input -> None.
Known limit: a trial that Duo reports under a bare paid name (no "trial" in the string) reads as True.
Every None carries dataCollection.status "error", so it is Not evaluated, never a fail.
"""
import json
from datetime import datetime

KEY = "confirmedLicensePurchased"
ENDPOINT = "GET /admin/v1/info/summary"
REQUIRED_PERMISSION = "Grant read information"
META = {"transformationId": KEY, "vendor": "Duo", "category": "iam"}

# Edition names as Duo writes them, lower-cased with any leading "duo " removed, and the
# Admin API edition codes (ENTERPRISE = Essentials, PLATFORM = Advantage, BEYOND = Premier).
PAID_EDITIONS = ["essentials", "advantage", "premier", "mfa", "access", "beyond",
                 "federal mfa", "federal access", "enterprise", "platform"]
FREE_EDITIONS = ["free", "personal"]


def create_response(result, api_errors=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None):
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": META["transformationId"], "vendor": META["vendor"],
                         "category": META["category"]},
        },
    }


def not_evaluated(problem, error_code, recommendation, extra=None):
    """Nothing measured: the key is None and dataCollection is "error", never False."""
    out = create_response({KEY: None, "duoEdition": None}, api_errors=[problem], fail_reasons=[problem],
                          recommendations=[recommendation])
    collection = out["additionalInfo"]["dataCollection"]
    collection["errorCode"] = error_code
    if extra:
        for k in extra:
            collection[k] = extra[k]
    return out


def decoded(value):
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except Exception:
            return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return None
    return value


def refusal_of(value):
    """Integration-Service's vendorErrorAsResponse marker, at the top level or one level down, else None."""
    if not isinstance(value, dict):
        return None
    marker = value.get("vendorErrorAsResponse")
    if isinstance(marker, dict):
        return marker
    for k in value:
        inner = value[k]
        if isinstance(inner, dict) and isinstance(inner.get("vendorErrorAsResponse"), dict):
            return inner["vendorErrorAsResponse"]
    return None


def is_error_body(value):
    if not isinstance(value, dict):
        return False
    if str(value.get("stat", "")).upper() == "FAIL" or value.get("error") or value.get("errorType"):
        return True
    code = value.get("statusCode")
    return isinstance(code, int) and not isinstance(code, bool) and code >= 400


def summary_of(value):
    """The info-summary object under any of the usual wrappers, else None."""
    data = value
    for _ in range(4):
        if not isinstance(data, dict) or is_error_body(data):
            return None
        if isinstance(data.get("data"), dict) and "validation" in data:
            data = data["data"]
            continue
        moved = False
        for k in ["response", "apiResponse", "api_response", "result", "Output"]:
            if isinstance(data.get(k), dict):
                data = data[k]
                moved = True
                break
        if not moved:
            break
    if not isinstance(data, dict) or is_error_body(data) or len(data) == 0:
        return None
    return data


def refused(marker):
    status = marker.get("status")
    body = decoded(marker.get("body"))
    code = body.get("code") if isinstance(body, dict) else None
    if status == 401 or code == 40101:
        # A refused signature or key, not a missing permission: the customer reconnects Duo.
        problem = ("Duo refused " + ENDPOINT + " with HTTP 401 (unauthorized): the Admin API integration key, "
                   "secret or hostname is not accepted. Nothing was measured; this is not a posture result.")
        return not_evaluated(problem, "vendor_refusal",
                             "Reconnect Duo with a valid Admin API integration key, secret key and API hostname.",
                             {"vendorStatus": 401})
    if status == 403 or code == 40301:
        problem = ("PERMISSION-NOT-GRANTED: Duo refused " + ENDPOINT + " (HTTP 403, code " + str(code)[:8]
                   + "). The Admin API application needs the \""
                   + REQUIRED_PERMISSION + "\" permission to report the account's edition. "
                   "Nothing was measured; this is not a posture result.")
        return not_evaluated(
            problem, "scope_not_granted",
            "In the Duo Admin Panel, open the Admin API application used for Spektrum and enable \""
            + REQUIRED_PERMISSION + "\"; the integration key and secret do not change.",
            {"requiredScope": REQUIRED_PERMISSION, "vendorStatus": 403})
    problem = "Duo refused " + ENDPOINT + " (HTTP " + str(status)[:5] + "); nothing was measured."
    return not_evaluated(problem, "vendor_refusal",
                         "Confirm the Duo Admin API credentials are valid and the application is enabled.")


def transform(input):
    try:
        raw = decoded(input)
        marker = refusal_of(raw)
        if marker is not None:
            return refused(marker)
        summary = summary_of(raw)
        if summary is None:
            return not_evaluated(
                "Duo's account summary (" + ENDPOINT + ") was not read: the body was empty, unreadable or an "
                "error. Nothing was measured.", "not_measured",
                "Confirm the Duo Admin API credentials are valid and the application has \""
                + REQUIRED_PERMISSION + "\".")
        edition = summary.get("edition")
        if not isinstance(edition, str) or not edition.strip():
            return not_evaluated(
                "NOT-AVAILABLE: vendor exposes no licence state. Duo's account summary (" + ENDPOINT
                + ") carries no edition for this account, so the purchased licence cannot be read from Duo.",
                "not_available",
                "Show the Duo subscription (Admin Panel > Billing) as evidence, or attest the licence.")
        shown = edition.strip()[:60]
        name = shown.lower()
        if name.startswith("duo "):
            name = name[4:].strip()
        summary_out = {"edition": shown, "endpoint": ENDPOINT}
        if "trial" in name:
            return create_response(
                {KEY: False, "duoEdition": shown},
                fail_reasons=["Duo reports the account edition as \"" + shown + "\": a trial, not a purchased licence (edition as reported by Duo; Duo includes trials)."],
                recommendations=["Purchase a Duo edition, or attest the licence if the trial has been converted."],
                input_summary=summary_out)
        if name in FREE_EDITIONS:
            return create_response(
                {KEY: False, "duoEdition": shown},
                fail_reasons=["Duo reports the account edition as \"" + shown + "\" (Duo Free): no purchased licence."],
                recommendations=["Purchase a paid Duo edition (Essentials, Advantage or Premier)."],
                input_summary=summary_out)
        if name in PAID_EDITIONS:
            # Duo's edition field "includes trials": the pass reason says so, so a reader weighs it.
            return create_response(
                {KEY: True, "duoEdition": shown},
                pass_reasons=["Paid Duo edition \"" + shown + "\", edition as reported by Duo (Duo includes trials)."],
                input_summary=summary_out)
        return not_evaluated(
            "Duo reported an edition this check does not recognise: \"" + shown + "\". Nothing was graded.",
            "not_measured",
            "Add the edition to this check's list of paid or free Duo editions.",
            {"duoEdition": shown})
    except Exception as e:
        return not_evaluated("The Duo licence check raised " + str(e)[:200] + "; nothing was graded.",
                             "not_measured", "Investigate the transformation error.")
