"""
Transformation: arePrivilegedAccountsCloudOnly
Vendor: Microsoft (Entra ID: Azure AD, Azure AD One-Click and Microsoft 365 integrations)
Category: Identity / Admin Accounts

Claim (IAM-004 Admin Account Segmentation): accounts holding privileged Entra directory roles are
cloud-only admin accounts, not synced from everyday on-premises Active Directory identities.
Pass = isEquals true.

WHY IT MATTERS. A Global Administrator that is synced from on-premises AD inherits that AD account's
password, its lifecycle and the security of every domain controller and sync server: a compromise of
on-premises AD becomes a compromise of the cloud tenant. Microsoft's guidance is that privileged Entra
roles are held by cloud-only accounts.

RULE. Every ENABLED user that holds a privileged Entra directory role (PRIVILEGED_ROLE_IDS, the same
set as areadminaccountsseparate.py so the two checks judge the same population) must have
`onPremisesSyncEnabled` not equal to true:

  * onPremisesSyncEnabled true   -> the account is synced from on-premises AD: a measured fail.
  * onPremisesSyncEnabled null   -> the account was never synced: cloud-only.
  * onPremisesSyncEnabled false  -> the account was synced once and is no longer; Entra is now its
                                    source of authority, so it is cloud-managed. Reported as a finding.

A non-empty `onPremisesImmutableId` on an account that is not synced is reported as a finding, not a
fail: it is set on former synced accounts and on accounts that sign in through a federated identity
provider, but it does not by itself show that either is the case. Telling federation apart needs the
tenant's domain list (GET /domains, Domain.Read.All), a permission the integrations do not hold, so it
is not read here (see PERMISSIONS).

Role holders that are service principals are not user accounts and are not judged. Disabled role holders
cannot sign in; they are counted and not judged. A role-assignable GROUP holding a privileged role is
not expanded by this read, so its members are unresolved and the result is not evaluated. Only ACTIVE
role assignments are read (roleAssignments); PIM-eligible assignments are not in this read.

INPUT. Two Microsoft Graph v1.0 list reads, merged by a two-step Integration-Service workflow:

    {"roleAssignments": <Graph list body>, "users": <Graph list body>}

from
    GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal($select=id)
        (method getDirectoryRoleAssignments, already on every Microsoft definition)
    GET /v1.0/users?$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,
        onPremisesImmutableId&$top=999
        (a NEW method, getUsersWithSyncState; onPremisesSyncEnabled is returned only on $select, so
         the existing getUsersWithLicenses read does not carry it)

`directoryRoles` (GET /v1.0/directoryRoles?$expand=members) is accepted as an alternative role source.

PERMISSIONS. Both reads need only RoleManagement.Read.Directory (or Directory.Read.All) and
User.Read.All, which the Microsoft integrations already hold for areAdminAccountsSeparate. No new
permission and no tenant re-consent.

FAIL CLOSED. An empty, null, unrecognised or error body (PSError, Graph {"error": {...}}, an HTTP
4xx/5xx envelope, an IS error status), a read with no enabled privileged user (every tenant has a
Global Administrator), a truncated read (@odata.nextLink), a role holder that cannot be resolved, or a
user read that does not carry onPremisesSyncEnabled returns arePrivilegedAccountsCloudOnly = None with
a dataCollection error, so the check reads "not evaluated", never pass or fail. A privileged account
shown to be synced is a measured fail, whatever else is missing.
"""

import json
from datetime import datetime


# ============================================================================
# Response Helpers (inline for RestrictedPython compatibility)
# ============================================================================

def extract_input(input_data):
    """Extract data and validation from input, handling both new and legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]

    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return unwrap(input_data), validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create a standardized transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}

    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
        "transformationId": "arePrivilegedAccountsCloudOnly",
        "vendor": "Microsoft",
        "category": "Identity",
    }
    if metadata:
        response_metadata.update(metadata)

    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or [],
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


# ============================================================================
# Transformation Logic
# ============================================================================

CRITERIA_KEY = "arePrivilegedAccountsCloudOnly"
SOURCE = "Microsoft Graph"
WRAPPER_KEYS = ["api_response", "apiResponse", "response", "result", "Output", "rawResponse"]
ERROR_STATUSES = ["error", "failure", "failed", "not available"]
MAX_NAMED = 5

# Entra built-in directory role TEMPLATE ids (identical in every tenant). Same set as
# areadminaccountsseparate.py in this folder and in 874a78ff-.../, so both IAM-004 checks judge
# the same privileged population.
PRIVILEGED_ROLE_IDS = [
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader (read-only but tenant-wide)
]


def short(value, limit=100):
    """Bound tenant-supplied names before they are echoed into evaluation reasons."""
    text = str(value)
    return text[:limit] + "..." if len(text) > limit else text


def unwrap(data):
    """Peel engine wrappers ({"apiResponse": ...}, {"Output": ...}) off a body."""
    for depth in range(4):
        if not isinstance(data, dict):
            return data
        found = None
        for key in WRAPPER_KEYS:
            if key in data and isinstance(data.get(key), (dict, list)):
                found = key
                break
        if found is None:
            return data
        data = data[found]
    return data


def parse_api_error(raw_error, source=None):
    """Parse a raw API error into a clean message and a recommendation."""
    raw_text = str(raw_error or "")
    raw_lower = raw_text.lower()
    src = source or "external service"

    if "401" in raw_text or "invalidauthenticationtoken" in raw_lower:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    if "403" in raw_text or "authorization_requestdenied" in raw_lower or "forbidden" in raw_lower:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                "Confirm the integration holds RoleManagement.Read.Directory (or Directory.Read.All) "
                "and User.Read.All with admin consent")
    if "404" in raw_text:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    if "429" in raw_text:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    if "500" in raw_text or "502" in raw_text or "503" in raw_text:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    if "timeout" in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    if "connection" in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")

    clean = raw_text[:80] + "..." if len(raw_text) > 80 else raw_text
    return (f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration")


def error_text(body):
    """Return the raw error text if this body is an error, else None."""
    if not isinstance(body, dict):
        return None
    if "PSError" in body:
        return str(body.get("PSError") or "PSError")
    err = body.get("error")
    if isinstance(err, dict):
        code = str(err.get("code") or err.get("statusCode") or "")
        message = str(err.get("message") or "")
        return (code + " " + message).strip() or "error"
    if isinstance(err, str) and err:
        code = body.get("statusCode", body.get("status_code", ""))
        return (str(code) + " " + err).strip()
    if err is True:
        return str(body.get("statusCode") or body.get("status_code") or "") + " error"
    for key in ["statusCode", "status_code"]:
        code = body.get(key)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return str(code) + " " + str(body.get("message") or "")
    status = body.get("status")
    if isinstance(status, str) and status.lower() in ERROR_STATUSES:
        return str(body.get("message") or body.get("errorMessage") or status)
    return None


def rows_of(body):
    """The `value` list of a Graph list body, or None when the body is not one."""
    body = unwrap(body)
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        return body["value"]
    return None


def is_truncated(body):
    body = unwrap(body)
    return isinstance(body, dict) and bool(body.get("@odata.nextLink"))


def lower_id(value):
    return str(value or "").strip().lower()


def odata_kind(obj):
    """'user', 'serviceprincipal', 'group' or '' from an @odata.type annotation."""
    if not isinstance(obj, dict):
        return ""
    text = str(obj.get("@odata.type") or "").lower()
    for kind in ["serviceprincipal", "group", "user"]:
        if text.endswith("." + kind) or text == kind:
            return kind
    return ""


def is_enabled(user):
    return str(user.get("accountEnabled")).lower() != "false"


def sync_state(user):
    """'synced', 'formerly', 'never' or 'unknown' from onPremisesSyncEnabled.

    Stored bodies carry booleans as strings ("True"/"true"), so both forms are read."""
    if "onPremisesSyncEnabled" not in user:
        return "unknown"
    value = user.get("onPremisesSyncEnabled")
    if value is None:
        return "never"
    text = str(value).strip().lower()
    if text == "true":
        return "synced"
    if text == "false":
        return "formerly"
    if text in ["", "none", "null"]:
        return "never"
    return "unknown"


def has_immutable_id(user):
    value = user.get("onPremisesImmutableId")
    return bool(value) and str(value).strip().lower() not in ["none", "null"]


def collect(data):
    """Return (assignments, role_members, users, api_errors, recommendations, truncated)."""
    api_errors = []
    recommendations = []
    truncated = []

    def note_error(raw, label):
        message, recommendation = parse_api_error(raw, source=SOURCE + label)
        api_errors.append(message)
        if recommendation not in recommendations:
            recommendations.append(recommendation)

    top_error = error_text(data)
    if top_error is not None:
        note_error(top_error, "")
        return None, None, None, api_errors, recommendations, truncated

    if not isinstance(data, dict):
        return None, None, None, api_errors, recommendations, truncated

    parts = {}
    for label in ["roleAssignments", "directoryRoles", "users"]:
        if label not in data:
            continue
        part = unwrap(data.get(label))
        part_error = error_text(part)
        if part_error is not None:
            note_error(part_error, " /" + label)
            continue
        rows = rows_of(part)
        if rows is None:
            api_errors.append(f"{SOURCE} /{label} returned an unrecognised body")
            continue
        if is_truncated(part):
            truncated.append(label)
        parts[label] = rows

    if str(data.get("paginationTruncated")).lower() == "true" and "pagination" not in truncated:
        truncated.append("pagination")
    stats = data.get("paginationStats")
    if isinstance(stats, dict):
        for label in sorted(stats):
            marker = stats.get(label)
            if isinstance(marker, dict) and str(marker.get("paginationTruncated")).lower() == "true" \
                    and label not in truncated:
                truncated.append(label)

    return (parts.get("roleAssignments"), parts.get("directoryRoles"), parts.get("users"),
            api_errors, recommendations, truncated)


def privileged_principals(assignments, directory_roles):
    """Map principal id -> kind ('user', 'serviceprincipal', 'group' or '') for privileged roles."""
    found = {}
    for assignment in assignments or []:
        if not isinstance(assignment, dict):
            continue
        role_id = lower_id(assignment.get("roleDefinitionId") or assignment.get("roleTemplateId"))
        if role_id not in PRIVILEGED_ROLE_IDS:
            continue
        principal = assignment.get("principal") if isinstance(assignment.get("principal"), dict) else {}
        pid = lower_id(assignment.get("principalId") or principal.get("id"))
        if pid:
            found[pid] = odata_kind(principal) or found.get(pid, "")
    for role in directory_roles or []:
        if not isinstance(role, dict):
            continue
        if lower_id(role.get("roleTemplateId")) not in PRIVILEGED_ROLE_IDS:
            continue
        for member in rows_of(role.get("members")) or []:
            if isinstance(member, dict) and lower_id(member.get("id")):
                mid = lower_id(member.get("id"))
                found[mid] = odata_kind(member) or found.get(mid, "")
    return found


def not_evaluated(validation, reasons, recommendations=None, summary=None, findings=None, result=None):
    out = {CRITERIA_KEY: None, "privilegedUserCount": 0, "syncedPrivilegedAccounts": 0,
           "unresolvedPrivilegedPrincipals": 0}
    if result:
        out.update(result)
        out[CRITERIA_KEY] = None
    return create_response(
        result=out,
        validation=validation,
        api_errors=reasons,
        fail_reasons=["Whether privileged accounts are cloud-only could not be confirmed: " + "; ".join(reasons)],
        recommendations=recommendations or [],
        input_summary=summary or {},
        additional_findings=findings or [],
    )


def transform(input):
    """Evaluate whether privileged Entra role holders are cloud-only (not synced from on-premises AD)."""
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(
                validation,
                ["Input validation failed: " + "; ".join(validation.get("errors", []))],
                ["Verify the Microsoft integration is configured correctly"],
            )

        assignments, directory_roles, users, api_errors, recommendations, truncated = collect(data)

        if (assignments is None and directory_roles is None) or users is None:
            if not api_errors:
                api_errors.append("Input carries no Microsoft Graph role assignment and user sync-state data")
                recommendations.append(
                    "Wire arePrivilegedAccountsCloudOnly to getDirectoryRoleAssignments and getUsersWithSyncState "
                    "(users with onPremisesSyncEnabled in $select)")
            return not_evaluated(validation, api_errors, recommendations)

        users_by_id = {}
        for user in users:
            if isinstance(user, dict) and lower_id(user.get("id")):
                users_by_id[lower_id(user.get("id"))] = user

        principals = privileged_principals(assignments, directory_roles)

        privileged_users = 0
        disabled = 0
        service_principals = 0
        unresolved = []
        unknown_state = []
        synced = []
        formerly = []
        immutable = []
        for pid in sorted(principals):
            kind = principals[pid]
            if kind == "serviceprincipal":
                service_principals = service_principals + 1
                continue
            if kind == "group":
                unresolved.append(short(pid, 60) + " (role-assignable group; members not read)")
                continue
            user = users_by_id.get(pid)
            if user is None:
                unresolved.append(short(pid, 60) + " (not in the user read)")
                continue
            privileged_users = privileged_users + 1
            if not is_enabled(user):
                disabled = disabled + 1
                continue
            name = short(user.get("userPrincipalName") or user.get("displayName") or pid)
            state = sync_state(user)
            if state == "synced":
                synced.append(name)
            elif state == "unknown":
                unknown_state.append(name)
            else:
                if state == "formerly":
                    formerly.append(name)
                if has_immutable_id(user):
                    immutable.append(name)

        enabled_users = privileged_users - disabled
        result = {
            CRITERIA_KEY: None,
            "privilegedUserCount": enabled_users,
            "syncedPrivilegedAccounts": len(synced),
            "unresolvedPrivilegedPrincipals": len(unresolved),
        }
        summary = {
            "privilegedPrincipals": len(principals),
            "privilegedUsers": privileged_users,
            "enabledPrivilegedUsers": enabled_users,
            "disabledPrivilegedUsers": disabled,
            "servicePrincipalAdmins": service_principals,
            "userCount": len(users_by_id),
            "syncStateUnknown": len(unknown_state),
            "truncated": truncated,
        }
        findings = []
        if service_principals > 0:
            findings.append(f"{service_principals} privileged role holder(s) are service principals (not judged)")
        if disabled > 0:
            findings.append(f"{disabled} privileged role holder(s) are disabled accounts (not judged)")
        if formerly:
            findings.append(f"{len(formerly)} privileged account(s) were synced from on-premises AD once and are "
                            f"now cloud-managed (onPremisesSyncEnabled false): " + "; ".join(formerly[:MAX_NAMED]))
        if immutable:
            findings.append(f"{len(immutable)} privileged account(s) are not synced but carry an on-premises "
                            f"immutable id (a former synced account, or one that signs in through a federated "
                            f"identity provider): " + "; ".join(immutable[:MAX_NAMED]))

        if synced:
            # A synced privileged account is a measured fail, whatever else is unresolved.
            reason = (f"{len(synced)} of {enabled_users} enabled privileged account(s) are synced from on-premises "
                      f"Active Directory (onPremisesSyncEnabled true): " + "; ".join(synced[:MAX_NAMED]))
            if len(synced) > MAX_NAMED:
                reason += " and " + str(len(synced) - MAX_NAMED) + " more"
            if unresolved or unknown_state:
                reason += "; also unresolved: " + "; ".join((unresolved + unknown_state)[:MAX_NAMED])
            result[CRITERIA_KEY] = False
            return create_response(
                result=result,
                validation=validation,
                fail_reasons=[reason],
                recommendations=[
                    "Hold privileged Entra roles with cloud-only accounts (for example on the onmicrosoft.com "
                    "domain), and remove privileged roles from accounts synced from on-premises AD"
                ],
                input_summary=summary,
                additional_findings=findings,
            )

        incomplete = list(api_errors)
        if truncated:
            incomplete.append("the read is truncated (more pages on " + ", ".join(truncated) + ")")
        if unresolved:
            incomplete.append(f"{len(unresolved)} privileged role holder(s) could not be resolved: "
                              + "; ".join(unresolved[:MAX_NAMED]))
        if unknown_state:
            incomplete.append(f"the user read does not carry onPremisesSyncEnabled for {len(unknown_state)} "
                              f"privileged account(s) (it is returned only on $select): "
                              + "; ".join(unknown_state[:MAX_NAMED]))
        if enabled_users == 0 and not unresolved:
            incomplete.append("no enabled user holds a privileged directory role; every tenant has a Global "
                              "Administrator, so the read is incomplete")

        if incomplete:
            return not_evaluated(
                validation, incomplete,
                recommendations + ["Read all role assignments and all users with onPremisesSyncEnabled in "
                                   "$select ($top=999, follow nextLink)"],
                summary, findings, result)

        result[CRITERIA_KEY] = True
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=[f"All {enabled_users} enabled privileged account(s) are cloud-only: none is synced from "
                          f"on-premises Active Directory"],
            input_summary=summary,
            additional_findings=findings,
        )

    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return create_response(
            result={CRITERIA_KEY: None, "privilegedUserCount": 0, "syncedPrivilegedAccounts": 0,
                    "unresolvedPrivilegedPrincipals": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[message],
            api_errors=[message],
            fail_reasons=[message],
        )
