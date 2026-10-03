"""
Transformation: isRBACImplemented
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion: "Admin Portal access is governed by role assignments (built-in or custom) rather than flat
all-or-nothing access." (isEquals true)

Data source: GET https://console.jumpcloud.com/api/users (IS method listAdministrators), the JumpCloud
administrator (console admin) list -- not /api/systemusers, which lists end users. The same call the JumpCloud
PowerShell module's Get-JCAdmin makes (https://www.powershellgallery.com/packages/JumpCloud, Public/Administrators/
Get-JCAdmin.ps1). Each record carries roleName (and, with multi-role, roleNames), enableMultiFactor, totpEnrolled
and suspended; the list is paged with limit/skip and carries totalCount. The x-api-key acts with the rights of the
administrator who owns it; no OAuth scope exists.

JumpCloud system roles (Get-JCAdmin roleName set): Administrator With Billing, Administrator, Manager,
Command Runner With Billing, Command Runner, Help Desk, Billing Only, Read Only; plus custom roles.

FULL-ADMIN roles are "Administrator With Billing" and "Administrator" (every administrative scope).
A SCOPED admin is an active administrator none of whose roles is full-admin and who is not Read Only only.
Read Only alone is not counted as evidence: Spektrum's own setup instructions ask every customer to create a
Read Only administrator for this integration, so that account would satisfy the check by itself.

Least-privilege bar (Microsoft's guidance for privileged roles: fewer than five global administrators): a scoped
admin alone is not role-based access if most people still hold full Administrator. The full-admin count must be 1
to 4 (MAX_FULL_ADMINS); JumpCloud always needs at least one Administrator With Billing.

Verdict:
  True   the full admin list was read, at least one active administrator holds only scoped roles, and 1 to 4
         active administrators hold full Administrator / Administrator With Billing.
  False  the full admin list was read and either every active administrator's role is readable and each is a full
         admin or Read Only only (flat access), or 5 or more active administrators hold full admin roles.
  None   (Unevaluated, dataCollection error) no complete admin list (null, {}, error/401/403, unrelated JSON,
         partial read vs totalCount), no active administrator, no readable full admin (the list cannot be
         complete), unreadable roles that could push the full-admin count past the bar, or a False that rests on an
         admin whose role cannot be read.

Does not prove: what a custom role grants, or provider (MSP) administrators, who are not in this list.
"""
import json
from datetime import datetime

KEY = "isRBACImplemented"
MAX_FULL_ADMINS = 4
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}
FULL_ADMIN_ROLES = ("administrator with billing", "administrator")
READ_ONLY_ROLES = ("read only",)


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


def truthy(value):
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


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
    """Lower-cased role names, or None when no role can be read."""
    names = []
    multi = admin.get("roleNames")
    if isinstance(multi, list):
        for name in multi:
            if isinstance(name, str) and name.strip():
                names.append(name.strip().lower())
    single = admin.get("roleName")
    if isinstance(single, str) and single.strip() and single.strip().lower() not in names:
        names.append(single.strip().lower())
    return names if names else None


def label(admin):
    """An opaque record id for counting; administrator emails are never copied into the output."""
    return str(admin.get("_id") or admin.get("id") or "unnamed")


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
        active = [a for a in records if not truthy(a.get("suspended"))]
        if not active:
            return unevaluated("No active JumpCloud administrator was returned; there is no admin access to "
                               "evaluate.", validation)
        full_admin = []
        read_only = []
        scoped = []
        unreadable = []
        for admin in active:
            names = role_names(admin)
            if names is None:
                unreadable.append(label(admin))
                continue
            if any([n in FULL_ADMIN_ROLES for n in names]):
                full_admin.append(label(admin))
            elif all([n in READ_ONLY_ROLES for n in names]):
                read_only.append(label(admin))
            else:
                scoped.append(", ".join(names))
        summary = {"administratorCount": len(records), "activeAdministratorCount": len(active),
                   "fullAdminCount": len(full_admin), "scopedAdminCount": len(scoped),
                   "readOnlyOnlyAdminCount": len(read_only), "unreadableRoleCount": len(unreadable)}
        result = {KEY: None, "activeAdministratorCount": len(active), "fullAdminCount": len(full_admin),
                  "scopedAdminCount": len(scoped), "readOnlyOnlyAdminCount": len(read_only)}
        if scoped and len(full_admin) > MAX_FULL_ADMINS:
            result[KEY] = False
            return create_response(
                result=result, validation=validation,
                fail_reasons=[str(len(full_admin)) + " active administrator(s) hold full Administrator (or "
                              "Administrator With Billing); least privilege allows at most "
                              + str(MAX_FULL_ADMINS) + ", even though " + str(len(scoped))
                              + " hold a scoped role"],
                recommendations=["Move administrators who do not need every scope to a scoped system role (Manager, "
                                 "Help Desk, Command Runner) or a custom role, keeping 1 to "
                                 + str(MAX_FULL_ADMINS) + " full administrators"],
                input_summary=summary)
        if scoped and unreadable and len(full_admin) + len(unreadable) > MAX_FULL_ADMINS:
            return unevaluated(str(len(unreadable)) + " active administrator(s) carry no readable role; if they are "
                               "full administrators the count exceeds " + str(MAX_FULL_ADMINS)
                               + ", so least privilege cannot be confirmed.", validation)
        if scoped and not full_admin:
            return unevaluated("No active administrator with a readable full Administrator role was found; JumpCloud "
                               "always has at least one, so the admin list or its roles are incomplete.", validation)
        if scoped:
            result[KEY] = True
            return create_response(
                result=result, validation=validation,
                pass_reasons=[str(len(scoped)) + " of " + str(len(active)) + " active administrator(s) hold a "
                              "scoped role rather than full Administrator (roles: " + "; ".join(sorted(set(scoped))[:10])
                              + "), and " + str(len(full_admin)) + " hold full Administrator (at most "
                              + str(MAX_FULL_ADMINS) + ")"],
                input_summary=summary)
        if unreadable:
            return unevaluated(str(len(unreadable)) + " of " + str(len(active)) + " active administrator(s) carry "
                               "no readable role, and no scoped administrator was found; role-based access cannot "
                               "be confirmed or ruled out.", validation)
        result[KEY] = False
        return create_response(
            result=result, validation=validation,
            fail_reasons=["Flat admin access: " + str(len(full_admin)) + " active administrator(s) hold full "
                          "Administrator (or Administrator With Billing) and " + str(len(read_only)) +
                          " hold Read Only only; none holds a scoped role"],
            recommendations=["Assign administrators who do not need every scope a scoped system role (Manager, "
                             "Help Desk, Command Runner) or a custom admin role, and keep full Administrator for "
                             "the few who need it"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
