"""
Transformation: isAPIAccountPermissionScoped
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion (bundle 133571e9, requirement 1faf3a63): "JumpCloud Service Accounts are issued with
least-privilege scopes rather than full admin rights."

Data source: GET https://console.jumpcloud.com/api/v2/service-accounts (IS method listServiceAccounts).
JumpCloud API 2.0, operation ServiceAccounts_ListServiceAccounts -- https://docs.jumpcloud.com/api/2.0/index.html
(spec https://docs.jumpcloud.com/api/2.0/index.yaml). Each ServiceAccount carries roleId and roleName
("the role associated with the account"; roleName is marked deprecated in favour of a /roles lookup but is
still returned). A service account inherits exactly the permissions of its role
(https://jumpcloud.com/support/service-account-for-apis).

FULL-ADMIN roles are the two JumpCloud system roles that carry every administrative scope:
"Administrator With Billing" (Super Admin) and "Administrator". Every other system role (Manager, Help Desk,
Read Only, Command Runner, Asset Manager, Billing Only, ...) and any custom role is a scoped role.

Verdict:
  True   the full inventory was read, it holds at least one service account, and none has a full-admin role.
  False  at least one service account holds a full-admin role (named in the reasons).
  None   (Unevaluated, dataCollection error) no complete service-account list (null, {}, error/403, unrelated
         JSON, partial read vs totalCount), an empty inventory (no service account exists to be scoped, and
         administrator API keys are not visible to this API), or an account whose role cannot be read.
"""
import json
from datetime import datetime

KEY = "isAPIAccountPermissionScoped"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}
FULL_ADMIN_ROLES = ("administrator with billing", "administrator")


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


def service_accounts(data):
    if not isinstance(data, dict):
        return None, "No JumpCloud service-account list in the response; nothing to evaluate."
    records = data.get("results")
    if not isinstance(records, list):
        return None, "No JumpCloud service-account list in the response; nothing to evaluate."
    if not all(isinstance(r, dict) for r in records):
        return None, "The response is not a list of JumpCloud service-account records."
    total = as_count(data.get("totalCount"))
    if total is None:
        return None, "The service-account list carries no totalCount; completeness cannot be confirmed."
    if len(records) < total:
        return None, ("Only " + str(len(records)) + " of " + str(total) +
                      " service accounts were read; a partial inventory is not evaluated.")
    return records, None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        records, problem = service_accounts(data)
        if problem:
            return unevaluated(problem, validation)
        if not records:
            return unevaluated("No JumpCloud service accounts exist, so there is no service-account scope to "
                               "evaluate (administrator API keys are not visible to this API).", validation)
        full_admin = []
        unreadable = 0
        for sa in records:
            role = sa.get("roleName")
            if not isinstance(role, str) or not role.strip():
                unreadable = unreadable + 1
                continue
            if role.strip().lower() in FULL_ADMIN_ROLES:
                full_admin.append((sa.get("name") or sa.get("objectId") or "unnamed") + " (" + role.strip() + ")")
        total = len(records)
        summary = {"serviceAccountCount": total, "fullAdminServiceAccountCount": len(full_admin),
                   "unreadableRoleCount": unreadable}
        if full_admin:
            return create_response(
                result={KEY: False, "serviceAccountCount": total, "fullAdminServiceAccountCount": len(full_admin)},
                validation=validation,
                fail_reasons=[str(len(full_admin)) + " of " + str(total) + " service account(s) hold a full-admin "
                              "role: " + ", ".join(full_admin[:10])],
                recommendations=["Re-link these service accounts to a scoped system role or a custom admin role "
                                 "that grants only the scopes the integration needs"],
                input_summary=summary)
        if unreadable:
            return unevaluated(str(unreadable) + " of " + str(total) + " service account(s) carry no role name; "
                               "their scope cannot be confirmed.", validation)
        return create_response(
            result={KEY: True, "serviceAccountCount": total, "fullAdminServiceAccountCount": 0},
            validation=validation,
            pass_reasons=["All " + str(total) + " JumpCloud service account(s) are linked to a scoped role; none "
                          "holds Administrator or Administrator With Billing"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
