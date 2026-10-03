"""
Transformation: superAdminMfaEnrollmentPercentage
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion: "Percentage of Administrator-with-Billing (Super Admin) accounts with MFA enrolled."
(greaterThanOrEqual / greaterThan 100: the Token-Service compares int(float(value)) >= int(threshold), so the value
must stay below 100 unless every account in scope is enrolled.)

Data source: GET https://console.jumpcloud.com/api/users (IS method listAdministrators), the JumpCloud
administrator (console admin) list, paged with limit/skip and carrying totalCount. Fields read per record:
roleName / roleNames, totpEnrolled (the administrator has enrolled a TOTP authenticator), enableMultiFactor (MFA is
required for the administrator) and suspended -- the field set the JumpCloud PowerShell module's Get-JCAdmin returns
(https://www.powershellgallery.com/packages/JumpCloud, Public/Administrators/Get-JCAdmin.ps1).

Accounts in scope: ACTIVE (not suspended) administrators holding a full-admin role -- "Administrator With Billing"
(the Super Admin the criterion names) and "Administrator", which carries every administrative scope except billing.
Including Administrator makes the check stricter, never looser; the Billing-only figure is reported separately as
administratorWithBillingMfaPercentage.

Enrolled: totpEnrolled is true. enableMultiFactor true with totpEnrolled false means MFA is required but the
administrator has not enrolled yet; that is NOT counted as enrolled.

Output: superAdminMfaEnrollmentPercentage = enrolled / in scope * 100, rounded DOWN to one decimal, so 100.0 only
when every account is enrolled. Also superAdminCount, mfaEnrolledSuperAdminCount, administratorWithBillingCount,
administratorWithBillingMfaPercentage.

Unevaluated (value None, dataCollection error): no complete admin list (null, {}, error/401/403, unrelated JSON,
partial read vs totalCount), no active full administrator, or an in-scope administrator with no totpEnrolled field.

Does not prove: WebAuthn or push factors an administrator may also hold (the admin list exposes TOTP enrolment
only), or provider (MSP) administrators, who are not in this list.
"""
import json
import math
from datetime import datetime

KEY = "superAdminMfaEnrollmentPercentage"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}
FULL_ADMIN_ROLES = ("administrator with billing", "administrator")
SUPER_ADMIN_ROLE = "administrator with billing"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    metadata.update(META)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": metadata,
        },
    }


def unevaluated(problem, validation=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem], api_errors=[problem])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def flag(value):
    """True / False for a boolean or a "true"/"false" string; None when absent or unreadable."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def administrators(data):
    if not isinstance(data, dict):
        return None, "No JumpCloud administrator list in the response; nothing to evaluate."
    records = data.get("results")
    if not isinstance(records, list):
        return None, "No JumpCloud administrator list in the response; nothing to evaluate."
    if not all(isinstance(r, dict) for r in records):
        return None, "The response is not a list of JumpCloud administrator records."
    total = as_count(data.get("totalCount"))
    if total is None:
        return None, "The administrator list carries no totalCount; completeness cannot be confirmed."
    if len(records) < total:
        return None, ("Only " + str(len(records)) + " of " + str(total) +
                      " administrators were read; a partial list is not evaluated.")
    return records, None


def role_names(admin):
    names = []
    multi = admin.get("roleNames")
    if isinstance(multi, list):
        for name in multi:
            if isinstance(name, str) and name.strip():
                names.append(name.strip().lower())
    single = admin.get("roleName")
    if isinstance(single, str) and single.strip() and single.strip().lower() not in names:
        names.append(single.strip().lower())
    return names


def label(admin):
    """An opaque record id for counting; administrator emails are never copied into the output."""
    return str(admin.get("_id") or admin.get("id") or "unnamed")


def percentage_down(part, whole):
    """part / whole * 100 rounded DOWN to one decimal: 100.0 only when part == whole."""
    return math.floor(part * 1000.0 / whole) / 10.0


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        records, problem = administrators(data)
        if problem:
            return unevaluated(problem, validation)
        in_scope = []
        no_role = []
        for admin in records:
            if flag(admin.get("suspended")) is True:
                continue
            names = role_names(admin)
            if not names:
                no_role.append(label(admin))
            elif any([n in FULL_ADMIN_ROLES for n in names]):
                in_scope.append((admin, SUPER_ADMIN_ROLE in names))
        if no_role:
            return unevaluated(str(len(no_role)) + " active administrator(s) carry no readable role, so the full "
                               "administrator population cannot be established.", validation)
        if not in_scope:
            return unevaluated("No active JumpCloud administrator with Administrator With Billing or Administrator "
                               "was returned; the percentage has no population.", validation)
        unreadable = [label(a) for (a, is_billing) in in_scope if flag(a.get("totpEnrolled")) is None]
        if unreadable:
            return unevaluated(str(len(unreadable)) + " of " + str(len(in_scope)) + " full administrator(s) carry "
                               "no totpEnrolled value; MFA enrolment cannot be counted.", validation)
        enrolled = [a for (a, is_billing) in in_scope if flag(a.get("totpEnrolled")) is True]
        missing = [a for (a, is_billing) in in_scope if flag(a.get("totpEnrolled")) is False]
        billing = [a for (a, is_billing) in in_scope if is_billing]
        billing_enrolled = [a for a in billing if flag(a.get("totpEnrolled")) is True]
        pct = percentage_down(len(enrolled), len(in_scope))
        billing_pct = percentage_down(len(billing_enrolled), len(billing)) if billing else None
        result = {KEY: pct, "superAdminCount": len(in_scope), "mfaEnrolledSuperAdminCount": len(enrolled),
                  "administratorWithBillingCount": len(billing),
                  "administratorWithBillingMfaPercentage": billing_pct}
        summary = {"administratorCount": len(records), "fullAdminInScope": len(in_scope),
                   "mfaEnrolled": len(enrolled), "notEnrolled": len(missing),
                   "administratorWithBillingCount": len(billing)}
        if not missing:
            return create_response(
                result=result, validation=validation,
                pass_reasons=["All " + str(len(in_scope)) + " active full administrator(s) (Administrator With "
                              "Billing or Administrator) have enrolled TOTP MFA"],
                input_summary=summary)
        pending = [label(a) for a in missing if flag(a.get("enableMultiFactor")) is True]
        off = [label(a) for a in missing if flag(a.get("enableMultiFactor")) is not True]
        fails = [str(len(missing)) + " of " + str(len(in_scope)) + " active full administrator(s) have not enrolled "
                 "MFA (" + str(pct) + "% enrolled)"]
        if off:
            fails.append("MFA not required for " + str(len(off)) + " of them")
        if pending:
            fails.append("MFA required but not yet enrolled for " + str(len(pending)) + " of them")
        return create_response(
            result=result, validation=validation, fail_reasons=fails,
            recommendations=["Require MFA for every JumpCloud administrator (Settings > Administrators > Require "
                             "Multi-Factor Authentication) and have each one enrol before the next sign-in"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
