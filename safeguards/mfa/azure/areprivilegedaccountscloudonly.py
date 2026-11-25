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

Role holders that are service principals are not user accounts and are not judged. The kind comes only
from the expanded principal's @odata.type. A privileged principal that is not in the user read and
carries no @odata.type is most likely a service principal, but it cannot be told apart from a user
missing from the read, so it stays unresolved (not evaluated, fail-closed) and the reason says so
explicitly, naming the fix (read the principal type, or supply service-principal ids). Disabled role holders
cannot sign in; they are counted and not judged. A role-assignable GROUP holding a privileged role is expanded
through its transitive member read (WI-3b, below): each user member is judged like a direct holder. A group whose
member list was not read whole (no read, an error or vendor error returned as data, @odata.nextLink still set,
a read that cannot be paired with the group ids, or a group read twice) stays unresolved and the result is not
evaluated. roleAssignments holds ACTIVE assignments only; PIM-eligible assignments are read when the workflow merges
roleEligibilityScheduleInstances (see INPUT), and are judged like active ones (a group is expanded the same way).

Names (C4): reasons never echo a user principal name or display name; an account is named by the first 8
characters of its object id ("user 1a2b3c4d..."), which is enough to find it in Entra.

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

PIM-eligible role holders, when the workflow supplies them:
    "roleEligibilityScheduleInstances": <Graph list body, every page read>
from GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances (RoleEligibilitySchedule.Read.Directory or
RoleManagement.Read.Directory; Entra ID P2). The instances in effect now (startDateTime not in the future, endDateTime
null or later) that hold a PRIVILEGED_ROLE_IDS role join the population; the result reports activeAdminCount and
eligibleAdminCount over the enabled privileged users (a holder of both is in both; privilegedUserCount is the
distinct total). Absent: the verdict is what it was and eligibleAssignmentsRead is false. Present but not read whole
(an error or vendor error returned as data, @odata.nextLink still set): not evaluated, like a truncated read.

Role-assignable groups (WI-3b), when the workflow supplies them:
    "roleGroups":       {"groupIds": [{"id": ...}, ...]}  (GET /v1.0/groups?$filter=isAssignableToRole eq true
                        &$select=id; only role-assignable groups can hold an Entra role)
    "roleGroupMembers": one GET /v1.0/groups/{id}/transitiveMembers?$select=id,onPremisesSyncEnabled body per
                        group id, in the same order (method getGroupTransitiveMembersSyncState)
A member is judged from the users read (accountEnabled, onPremisesSyncEnabled), so a member missing from it is
unresolved. Nested groups in the transitive read are skipped (their users are listed too).

PERMISSIONS. Both reads need only RoleManagement.Read.Directory (or Directory.Read.All) and
User.Read.All, which the Microsoft integrations already hold for areAdminAccountsSeparate. No new
permission and no tenant re-consent.

FAIL CLOSED. An empty, null, unrecognised or error body (PSError, Graph {"error": {...}}, an HTTP
4xx/5xx envelope, an IS error status), a read with no enabled privileged user (every tenant has a
Global Administrator), a truncated read (@odata.nextLink, on any read including the PIM eligibility read), a role
holder that cannot be resolved, or a
user read that does not carry onPremisesSyncEnabled returns arePrivilegedAccountsCloudOnly = None with
a dataCollection error, so the check reads "not evaluated", never pass or fail. A privileged account
shown to be synced is a measured fail, whatever else is missing.
"""

import json
from datetime import datetime, timezone


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


def account_ref(pid):
    """A partial object id for reasons: enough to find the account in Entra, no personal data (C4)."""
    return "user " + str(pid)[:8] + "..."


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
    """True when the read carries any truncation marker (see truncation_flag)."""
    return bool(truncation_flag(unwrap(body)))


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
        if label == "roleAssignments":
            # Read whole (a page list too) or not at all: PIM-eligible holders only add to a readable active read.
            rows, problem, flag = active_assignment_rows(data.get(label))
            if problem:
                api_errors.append(problem)
                continue
        else:
            # An error marker anywhere on the read or its wrappers, or no list, is not a read of this part.
            pages, flag, problem = read_pages(data.get(label))
            if problem:
                api_errors.append(f"{SOURCE} /{label} cannot be read: {problem}")
                continue
            rows = [row for page in pages for row in page.get("value")]
        if flag:
            truncated.append(label)
        parts[label] = rows

    if ELIGIBLE_KEY in data and "roleAssignments" not in data:
        # An eligibility read never stands in for a missing active read, whatever directoryRoles holds.
        api_errors.append(ACTIVE_MISSING)

    workflow = workflow_truncation(data, (ELIGIBLE_KEY,))
    if workflow:
        truncated.append("the workflow read: " + workflow)

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


# ----------------------------------------------------------------------------- PIM-eligible role holders
# A tenant that uses Privileged Identity Management (PIM) holds admin roles as ELIGIBLE assignments, which
# GET /roleManagement/directory/roleAssignments (ACTIVE assignments only) does not return. When the workflow also
# merges GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances (every page read) under ELIGIBLE_KEY,
# its principals join the admin population (RoleEligibilitySchedule.Read.Directory or RoleManagement.Read.Directory;
# Entra ID P2 for PIM). Key absent (workflow not updated, or no P2): behaviour is unchanged and the output says
# eligibleAssignmentsRead false. Key present but not read whole (an error or vendor error returned as data, an
# @odata.nextLink still set, a truncation marker, a body that is not a list): the admin population is incomplete.
ELIGIBLE_KEY = "roleEligibilityScheduleInstances"
ELIGIBLE_ENDPOINT = "GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
ELIGIBLE_WRAPPERS = ["api_response", "apiResponse", "response", "result", "Output", "rawResponse", "data"]
ELIGIBLE_NOT_READ = ("PIM-eligible role assignments were not read (no " + ELIGIBLE_KEY + " in the input), so "
                     "administrators who hold a privileged role only through PIM eligibility are not in this result")


def eligibility_time(value):
    """A UTC datetime from Graph's ISO 8601 text ('2026-01-01T00:00:00Z', optional fraction), else None."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if len(raw) < 19 or raw[10] not in ("T", "t", " "):
        return None
    tail = raw[19:]
    if tail.startswith("."):
        index = 1
        while index < len(tail) and tail[index].isdigit():
            index = index + 1
        tail = tail[index:]
    if tail not in ("", "Z", "z", "+00:00"):
        return None
    try:
        return datetime.fromisoformat(raw[:10] + "T" + raw[11:19]).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def eligibility_in_effect(row, now):
    """False only for an instance shown to have ended (endDateTime at or before now) or not yet begun. An unreadable
    or missing date keeps the instance in, so data that cannot be read never narrows the admin population."""
    start = eligibility_time(row.get("startDateTime"))
    end = eligibility_time(row.get("endDateTime"))
    if start is not None and start > now:
        return False
    if end is not None and end <= now:
        return False
    return True


def marker_flag(obj):
    """paginationTruncated / truncated / iterateTruncated set on obj itself or under its response_metadata,
    metadata or pagination block (the markers Integration-Service and the workflow engine set on a read they
    stopped early), as 'block.name'; '' when none is set."""
    if not isinstance(obj, dict):
        return ""
    blocks = [("", obj)]
    for k in ("response_metadata", "metadata", "pagination"):
        if isinstance(obj.get(k), dict):
            blocks.append((k + ".", obj.get(k)))
    for prefix, block in blocks:
        for k in ("paginationTruncated", "truncated", "iterateTruncated"):
            value = block.get(k)
            number = isinstance(value, (int, float)) and not isinstance(value, bool)
            if value is True or (number and value != 0) or str(value).strip().lower() in ("true", "1", "yes"):
                return prefix + k
    return ""


def link_flag(obj):
    """'@odata.nextLink' or '_links.next' when obj still carries a next-page link, else ''."""
    if not isinstance(obj, dict):
        return ""
    if str(obj.get("@odata.nextLink") or "").strip() not in ("", "None", "null"):
        return "@odata.nextLink"
    links = obj.get("_links")
    if isinstance(links, dict) and isinstance(links.get("next"), dict):
        if str(links.get("next").get("href") or "").strip() not in ("", "None", "null"):
            return "_links.next"
    return ""


def truncation_flag(obj):
    """The truncation marker set on obj, '' when none: a next-page link (link_flag) or a marker (marker_flag)."""
    return link_flag(obj) or marker_flag(obj)


def cut_text(flag):
    """'only part of it was read (...)' for a truncation marker from truncation_flag."""
    if flag in ("@odata.nextLink", "_links.next"):
        return "only part of it was read (" + flag + " remains)"
    return "only part of it was read (" + flag + " is set)"


def error_marker(obj):
    """Why obj (a body or a wrapper around one) carries an error marker, '' when it carries none: a vendor
    error returned as data, PSError, a non-empty error or errors, success false, an error status word, or an
    HTTP status (statusCode, status_code, httpStatus, http_status, status) of 400 or more."""
    if not isinstance(obj, dict):
        return ""
    if "vendorErrorAsResponse" in obj:
        return "Microsoft Graph refused the read (vendor error returned as data)"
    if "PSError" in obj or obj.get("error") or obj.get("errors"):
        return "Microsoft Graph returned an error"
    if obj.get("success") is False or str(obj.get("success")).strip().lower() == "false":
        return "the read reported success false"
    for k in ("statusCode", "status_code", "httpStatus", "http_status", "status"):
        code = obj.get(k)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Microsoft Graph answered HTTP " + str(code)
    if str(obj.get("status") or "").strip().lower() in ("error", "failure", "failed", "fail", "not available"):
        return "the read reported an error status"
    return ""


PAGE_MARKERS = ("value", "error", "errors", "vendorErrorAsResponse", "PSError", "statusCode", "status_code",
                "httpStatus", "success")


def read_pages(body):
    """(pages, flag, problem) for one Graph read: a list body, a bare list of rows, or a list of pages, under any
    engine wrapper. Every wrapper and page is checked for an error marker (problem) and a truncation marker (flag).
    In a list of pages the read is whole when the LAST page has no next-page link: earlier pages of a fully read
    list keep theirs. Any other truncation marker on any page or wrapper is a cut-off read."""
    flag = ""
    for attempt in range(5):
        if not isinstance(body, dict):
            break
        problem = error_marker(body)
        if problem:
            return None, flag, problem
        if not flag:
            flag = truncation_flag(body)
        if "value" in body:
            break
        moved = False
        for k in ELIGIBLE_WRAPPERS:
            if isinstance(body.get(k), (dict, list)):
                body = body[k]
                moved = True
                break
        if not moved:
            break
    if isinstance(body, list) and len(
            [p for p in body if isinstance(p, dict) and len([k for k in PAGE_MARKERS if k in p]) > 0]) > 0:
        pages = body
    elif isinstance(body, list):
        pages = [{"value": body}]
    else:
        pages = [body]
    last = len(pages) - 1
    for index, page in enumerate(pages):
        if not isinstance(page, dict):
            return None, flag, "the body is not an object"
        problem = error_marker(page)
        if problem:
            return None, flag, problem
        if not isinstance(page.get("value"), list):
            return None, flag, "the body carries no value list"
        if not flag:
            flag = marker_flag(page) or (link_flag(page) if index == last else "")
    return pages, flag, ""


def workflow_truncation(data, skip):
    """The truncation marker the workflow set for the whole merged read, '' when none: a marker on the merged body
    itself (paginationTruncated / truncated / iterateTruncated, or under response_metadata, metadata or pagination)
    or under paginationStats.<any read> except the keys in `skip`, which their own reader judges."""
    if not isinstance(data, dict):
        return ""
    flag = marker_flag(data)
    if flag:
        return flag
    stats = data.get("paginationStats")
    if isinstance(stats, dict):
        for name in sorted(stats):
            if name not in skip and truncation_flag(stats.get(name)):
                return "paginationStats." + str(name) + "." + truncation_flag(stats.get(name))
    return ""


def eligibility_rows(data, now):
    """(rows, problem, ended) for the PIM eligibility read.
    Absent: (None, '', 0). Present but not read whole: (None, problem, 0). Read whole: the instances in effect at
    `now`, and how many were left out because they had ended or not yet begun. An error marker or a truncation
    marker on the body, a wrapper or a page (see read_pages), or under paginationStats.roleEligibilityScheduleInstances,
    makes the read incomplete: eligible admins were not fully read, so the result can never pass on them."""
    if not isinstance(data, dict) or ELIGIBLE_KEY not in data:
        return None, "", 0
    incomplete = ("the PIM role eligibility read (" + ELIGIBLE_ENDPOINT + ") is incomplete, so eligible admins "
                  "were not fully read: ")
    pages, flag, problem = read_pages(data.get(ELIGIBLE_KEY))
    stats = data.get("paginationStats")
    if not flag and isinstance(stats, dict) and truncation_flag(stats.get(ELIGIBLE_KEY)):
        flag = "paginationStats." + ELIGIBLE_KEY + "." + truncation_flag(stats.get(ELIGIBLE_KEY))
    if problem:
        return None, incomplete + problem, 0
    if flag:
        return None, incomplete + cut_text(flag), 0
    rows = []
    ended = 0
    for page in pages:
        for row in page.get("value"):
            if not isinstance(row, dict) or not str(row.get("principalId") or "").strip() \
                    or not str(row.get("roleDefinitionId") or "").strip():
                return None, incomplete + "an instance is not an object with a principalId and a roleDefinitionId", 0
            if eligibility_in_effect(row, now):
                rows.append(row)
            else:
                ended = ended + 1
    return rows, "", ended


# ----------------------------------------------------------------------------- ACTIVE role assignment read
# PIM-eligible holders only ADD to an active population that was read. When the active read (roleAssignments) is
# missing, carries an error marker anywhere on it or its wrappers, or holds a row that does not name its principal
# and role, eligibility data never stands in for it: the result is not evaluated.
ACTIVE_ENDPOINT = "GET /v1.0/roleManagement/directory/roleAssignments"
ACTIVE_MISSING = ("the active role assignment read (" + ACTIVE_ENDPOINT + ") is missing; PIM-eligible holders "
                  "never stand in for the active admins")


def active_assignment_rows(body):
    """(rows, problem, flag) for the ACTIVE role assignment read (see read_pages for the shapes read). problem is
    set when the read is missing, carries an error marker, or holds a row that is not an object with a principalId
    (or principal.id) and a roleDefinitionId; flag names a truncation marker for the caller to report."""
    prefix = "the active role assignment read (" + ACTIVE_ENDPOINT + ") "
    if body is None:
        return None, ACTIVE_MISSING, ""
    pages, flag, problem = read_pages(body)
    if problem:
        return None, prefix + "cannot be read: " + problem, flag
    rows = []
    for page in pages:
        for row in page.get("value"):
            principal = {}
            if isinstance(row, dict) and isinstance(row.get("principal"), dict):
                principal = row.get("principal")
            if not isinstance(row, dict) or not str(row.get("principalId") or principal.get("id") or "").strip() \
                    or not str(row.get("roleDefinitionId") or "").strip():
                return None, (prefix + "cannot be read: an assignment is not an object naming its principal and "
                              "its roleDefinitionId"), flag
            rows.append(row)
    return rows, "", flag


def eligible_principals(rows):
    """Map principal id -> kind for the PIM-eligible instances (in effect now) of privileged roles."""
    found = {}
    for row in rows or []:
        if lower_id(row.get("roleDefinitionId") or row.get("roleTemplateId")) not in PRIVILEGED_ROLE_IDS:
            continue
        principal = row.get("principal") if isinstance(row.get("principal"), dict) else {}
        pid = lower_id(row.get("principalId") or principal.get("id"))
        if pid:
            found[pid] = odata_kind(principal) or found.get(pid, "")
    return found


def role_group_members(data):
    """{lower-case group id: member rows read whole, or None} from roleGroups/roleGroupMembers paired by position.
    {} when the reads are absent or cannot be paired."""
    holder = data.get("roleGroups") if isinstance(data.get("roleGroups"), dict) else {}
    ids = holder.get("groupIds")
    bodies = data.get("roleGroupMembers")
    out = {}
    if not isinstance(ids, list) or not isinstance(bodies, list) or len(ids) != len(bodies):
        return out
    for index in range(len(ids)):
        entry = ids[index]
        gid = lower_id(entry.get("id") if isinstance(entry, dict) else entry)
        if not gid:
            continue
        if gid in out:
            out[gid] = None
            continue
        body = unwrap(bodies[index])
        rows = rows_of(body)
        if (isinstance(body, list) or error_text(body) is not None or rows is None or is_truncated(body)
                or "vendorErrorAsResponse" in body or body.get("paginationTruncated") is True):
            out[gid] = None
            continue
        if [r for r in rows if not isinstance(r, dict) or not lower_id(r.get("id"))]:
            out[gid] = None
            continue
        out[gid] = rows
    return out


def expand_groups(principals, data, origins=None):
    """Replace each group principal whose transitive members were read whole by its members (kind 'expanded' marks
    the group itself resolved). Returns how many principals were added through a group. `origins` (principal id ->
    {"active": bool, "eligible": bool}) passes a group's active/eligible origin on to its members."""
    expanded = role_group_members(data)
    added = 0
    for gid in sorted([p for p in principals if principals[p] == "group"]):
        rows = expanded.get(gid)
        if rows is None:
            continue
        principals[gid] = "expanded"
        for member in rows:
            mid = lower_id(member.get("id"))
            kind = odata_kind(member)
            if kind == "group":
                continue
            if origins is not None and gid in origins:
                mark = origins.get(mid) or {"active": False, "eligible": False}
                mark["active"] = mark["active"] or origins[gid]["active"]
                mark["eligible"] = mark["eligible"] or origins[gid]["eligible"]
                origins[mid] = mark
            if mid in principals:
                continue
            principals[mid] = kind
            added = added + 1
    return added


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
        origins = {}
        for pid in principals:
            origins[pid] = {"active": True, "eligible": False}
        eligible_rows, eligible_problem, eligible_ended = eligibility_rows(data, datetime.now(timezone.utc))
        eligible_read = eligible_rows is not None
        eligible = eligible_principals(eligible_rows)
        for pid in eligible:
            if pid not in principals or not principals[pid]:
                principals[pid] = eligible[pid]
            mark = origins.get(pid) or {"active": False, "eligible": False}
            mark["eligible"] = True
            origins[pid] = mark
        if eligible_problem:
            api_errors.append(eligible_problem)
        through_groups = expand_groups(principals, data, origins)

        privileged_users = 0
        active_users = 0
        eligible_users = 0
        disabled = 0
        service_principals = 0
        unresolved = []
        untyped = []
        unknown_state = []
        synced = []
        formerly = []
        immutable = []
        for pid in sorted(principals):
            kind = principals[pid]
            if kind == "expanded":
                continue
            if kind == "serviceprincipal":
                service_principals = service_principals + 1
                continue
            if kind == "group":
                unresolved.append(short(pid, 60) + " (role-assignable group; members not read whole)")
                continue
            user = users_by_id.get(pid)
            if user is None:
                if kind == "user":
                    unresolved.append(short(pid, 60) + " (a user not in the user read)")
                else:
                    untyped.append(short(pid, 60))
                    unresolved.append(short(pid, 60) + " (not in the user read and the role assignment carries no "
                                      "principal @odata.type: most likely a service principal or other non-user "
                                      "object, but it cannot be told apart from a user missing from the read)")
                continue
            privileged_users = privileged_users + 1
            if not is_enabled(user):
                disabled = disabled + 1
                continue
            origin = origins.get(pid) or {"active": False, "eligible": False}
            if origin["active"]:
                active_users = active_users + 1
            if origin["eligible"]:
                eligible_users = eligible_users + 1
            name = account_ref(pid)
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
            "activeAdminCount": active_users,
            "eligibleAdminCount": eligible_users if eligible_read else None,
            "eligibleAssignmentsRead": eligible_read,
        }
        summary = {
            "privilegedPrincipals": len([p for p in principals if principals[p] != "expanded"]),
            "privilegedPrincipalsThroughGroups": through_groups,
            "privilegedUsers": privileged_users,
            "enabledPrivilegedUsers": enabled_users,
            "disabledPrivilegedUsers": disabled,
            "servicePrincipalAdmins": service_principals,
            "userCount": len(users_by_id),
            "syncStateUnknown": len(unknown_state),
            "untypedPrincipalsNotInUserRead": len(untyped),
            "truncated": truncated,
            "activeAdminUsers": active_users,
            "eligibleAdminUsers": eligible_users if eligible_read else None,
            "eligibleAssignmentsRead": eligible_read,
            "eligibleInstancesNotInEffect": eligible_ended,
        }
        findings = []
        if not eligible_read and not eligible_problem:
            findings.append(ELIGIBLE_NOT_READ)
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
            incomplete.append("no enabled user holds a privileged directory role" + (
                ", active or PIM-eligible" if eligible_read else " (PIM-eligible assignments were not read)")
                + "; every tenant has a Global Administrator, so the read is incomplete")

        extra_recommendations = []
        if untyped:
            incomplete.append(f"{len(untyped)} privileged role holder(s) are not in the user read and carry no "
                              f"@odata.type on the expanded principal, so this check stays not evaluated on every "
                              f"run until their type is read; they are most likely service principals (automation "
                              f"apps holding a role such as Application Administrator)")
            extra_recommendations.append(
                "Have the role-assignment read return the principal type (expand principal so @odata.type is "
                "present) or add the tenant's service-principal ids to the workflow, so non-user role holders are "
                "recognised instead of left unresolved")
        if incomplete:
            return not_evaluated(
                validation, incomplete,
                recommendations + ["Read all role assignments and all users with onPremisesSyncEnabled in "
                                   "$select ($top=999, follow nextLink)"] + extra_recommendations,
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
