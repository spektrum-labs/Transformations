"""
Transformation: areAdminAccountsSeparate (Azure AD One-Click, role-assignment feed)
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management

Criterion: "Administrator accounts segmented from standard user accounts" -- every human account holding a
privileged Entra directory role is a dedicated admin identity with no mailbox (no mail address and no
Exchange-bearing licence), the same intent as the MS 365 (874a78ff) check, answered from Graph instead of the
client-secret PowerShell Lambda that One-Click cannot use.

Data source: IS workflow areAdminAccountsSeparate on Azure AD (One-Click) cde89168, two merged Graph reads:
  roleAssignments  GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=principal
                   https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments
                   (RoleManagement.Read.Directory or Directory.Read.All)
  users            GET https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,mail,accountEnabled,assignedLicenses&$top=999
                   https://learn.microsoft.com/en-us/graph/api/user-list (User.Read.All)
Input: {"roleAssignments": {"value": [...]}, "users": {"value": [...]}} (each may also arrive unwrapped).
Optional third read, PIM-eligible role holders (roleAssignments holds ACTIVE assignments only):
  roleEligibilityScheduleInstances
                   GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances
                   https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityscheduleinstances
                   (every page read; a Graph body, a bare list or a list of pages). The instances in effect now
                   (startDateTime not in the future, endDateTime null or later) are judged exactly like active
                   assignments: a privileged user joins the admin population, a group holder is unevaluated.
                   Absent: the verdict is what it was and eligibleAssignmentsRead is false. Present but not read
                   whole (error or vendor error as data, @odata.nextLink): unevaluated, like a paged active feed.

Privileged roles are Entra built-in role TEMPLATE ids (identical in every tenant), per
https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference .
Service-principal holders are not accounts a person signs in with and are excluded (counted in the summary).

Verdict:
  True   both feeds complete, at least one human privileged admin, and none has a mail address or an
         Exchange-bearing licence.
  False  at least one privileged human admin has a mail address or an Exchange-bearing licence.
  None   (Unevaluated, dataCollection error) a missing or error feed, a paged feed (@odata.nextLink present:
         only the first page was read), a role held by a group (members not read), a privileged user absent
         from the complete user feed, or no human privileged admin at all (active or, when read, PIM-eligible).
Names (C4): reasons name an account by the first 8 characters of its object id, never its UPN.
"""
import json
from datetime import datetime, timezone

KEY = "areAdminAccountsSeparate"

PRIVILEGED_ROLE_IDS = (
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
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader
)

# SKU ids that include an Exchange Online mailbox (Microsoft product-names-and-service-plan-identifiers list).
# Non-exhaustive: the mail-attribute test backstops SKUs not listed here.
MAIL_EXCHANGE_SKU_IDS = (
    "4b9405b0-7788-4568-add1-99614e63306e",  # EXCHANGESTANDARD
    "efb87545-963c-4f51-83ff-779edf226046",  # EXCHANGEENTERPRISE
    "6fd2c87f-b296-42f0-b197-1e91e994b900",  # ENTERPRISEPACK (Office 365 E3)
    "c7df2760-2c81-4ef7-b578-5b5392b571df",  # ENTERPRISEPREMIUM (Office 365 E5)
    "05e9a617-0261-4cee-bb44-138d3ef5d965",  # SPE_E3 (Microsoft 365 E3)
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06",  # SPE_E5 (Microsoft 365 E5)
    "3b555118-da6a-4418-894f-7df1e2096870",  # O365_BUSINESS_ESSENTIALS
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3",  # O365_BUSINESS_PREMIUM
    "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",  # SPB (Microsoft 365 Business Premium)
)


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "areAdminAccountsSeparate_roleassignments",
                         "vendor": "Microsoft", "category": "Identity"},
        },
    }


def unevaluated(problem, validation=None, summary=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem],
                           api_errors=[problem], input_summary=summary)


def graph_list(feed, name):
    """(records, problem) for one Graph collection feed."""
    if not isinstance(feed, dict):
        return None, "The " + name + " feed is missing; nothing to evaluate."
    pages, flag, problem = read_pages(feed)
    if problem:
        return None, "The " + name + " feed cannot be read (" + problem + "); not evaluated."
    if flag:
        return None, "The " + name + " feed was not read to the end (" + flag + "); not evaluated."
    records = [row for page in pages for row in page.get("value")]
    if not all(isinstance(r, dict) for r in records):
        return None, "The " + name + " feed is not a list of objects."
    return records, None


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


def account_ref(pid):
    """A partial object id for reasons: enough to find the account in Entra, no personal data (C4)."""
    return "user " + str(pid)[:8] + "..."


def principal_type(assignment):
    principal = assignment.get("principal")
    if isinstance(principal, dict):
        t = principal.get("@odata.type")
        if isinstance(t, str):
            return t.lower()
    return ""


def has_mailbox(user):
    mail = user.get("mail")
    if isinstance(mail, str) and mail.strip():
        return True
    for lic in user.get("assignedLicenses") or []:
        if isinstance(lic, dict):
            sku = lic.get("skuId")
            if isinstance(sku, str) and sku.lower() in MAIL_EXCHANGE_SKU_IDS:
                return True
    return False


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if not isinstance(data, dict):
            return unevaluated("No role-assignment and user feeds in the response; nothing to evaluate.", validation)
        workflow = workflow_truncation(data, (ELIGIBLE_KEY,))
        if workflow:
            return unevaluated("The workflow read was not read to the end (" + workflow + "); not evaluated.",
                               validation)
        # The ACTIVE read must be whole and readable: an error marker, a row with no principal or roleDefinitionId,
        # or a missing read is not evaluated, and PIM-eligible holders never stand in for it.
        assignments, problem, flag = active_assignment_rows(data.get("roleAssignments"))
        if problem:
            return unevaluated(problem[:1].upper() + problem[1:] + "; not evaluated.", validation)
        if flag:
            return unevaluated("The roleAssignments feed was not read to the end (" + flag + "); not evaluated.",
                               validation)
        users, problem = graph_list(data.get("users"), "users")
        if problem:
            return unevaluated(problem, validation)
        if not users:
            return unevaluated("The user feed is empty; admin accounts cannot be matched.", validation)
        if not all("assignedLicenses" in u for u in users):
            return unevaluated("The user feed does not carry assignedLicenses; licences cannot be judged.", validation)

        users_by_id = {}
        for u in users:
            if isinstance(u.get("id"), str):
                users_by_id[u["id"]] = u

        eligible, problem, eligible_ended = eligibility_rows(data, datetime.now(timezone.utc))
        if problem:
            return unevaluated(problem, validation)
        eligible_read = eligible is not None

        admin_user_ids = []
        active_ids = []
        eligible_ids = []
        sp_holders = 0
        group_holders = 0
        unknown_holders = 0
        tagged = [(a, active_ids) for a in assignments] + [(e, eligible_ids) for e in (eligible or [])]
        for a, kind_ids in tagged:
            if a.get("roleDefinitionId") not in PRIVILEGED_ROLE_IDS:
                continue
            pid = a.get("principalId")
            ptype = principal_type(a)
            if ptype.endswith("serviceprincipal"):
                sp_holders = sp_holders + 1
            elif ptype.endswith("group"):
                group_holders = group_holders + 1
            elif ptype.endswith("user") or (ptype == "" and pid in users_by_id):
                if pid not in admin_user_ids:
                    admin_user_ids.append(pid)
                if pid not in kind_ids:
                    kind_ids.append(pid)
            else:
                unknown_holders = unknown_holders + 1

        summary = {"privilegedUserAdmins": len(admin_user_ids), "privilegedServicePrincipals": sp_holders,
                   "privilegedGroups": group_holders, "userCount": len(users),
                   "activeAdminUsers": len(active_ids),
                   "eligibleAdminUsers": len(eligible_ids) if eligible_read else None,
                   "eligibleAssignmentsRead": eligible_read, "eligibleInstancesNotInEffect": eligible_ended}
        findings = [] if eligible_read else [ELIGIBLE_NOT_READ]
        if group_holders:
            return unevaluated(str(group_holders) + " privileged role assignment(s) are held by groups whose members "
                               "were not read; admin separation cannot be confirmed.", validation, summary)
        if unknown_holders:
            return unevaluated(str(unknown_holders) + " privileged role assignment(s) name a principal of unknown "
                               "type; admin separation cannot be confirmed.", validation, summary)
        missing = [pid for pid in admin_user_ids if pid not in users_by_id]
        if missing:
            return unevaluated(str(len(missing)) + " privileged user(s) are absent from the user feed; not evaluated.",
                               validation, summary)
        if not admin_user_ids:
            return unevaluated("No user holds a privileged directory role" + (
                ", active or PIM-eligible" if eligible_read else " (PIM-eligible assignments were not read)")
                + "; there is no admin account to judge.", validation, summary)

        with_mail = []
        for pid in admin_user_ids:
            u = users_by_id[pid]
            if has_mailbox(u):
                with_mail.append(account_ref(pid))  # C4: no user principal name in a reason
        summary["adminsWithMailbox"] = len(with_mail)
        result = {KEY: len(with_mail) == 0, "adminCount": len(admin_user_ids), "adminsWithMailbox": len(with_mail),
                  "activeAdminCount": len(active_ids),
                  "eligibleAdminCount": len(eligible_ids) if eligible_read else None,
                  "eligibleAssignmentsRead": eligible_read}
        if with_mail:
            return create_response(
                result=result, validation=validation,
                fail_reasons=[str(len(with_mail)) + " of " + str(len(admin_user_ids)) + " privileged admin account(s) "
                              "have a mailbox (mail address or Exchange licence): " + ", ".join(with_mail[:10])],
                recommendations=["Give each administrator a separate, unlicensed admin-only account and remove "
                                 "privileged roles from everyday mail-enabled accounts"],
                input_summary=summary, additional_findings=findings)
        return create_response(
            result=result, validation=validation,
            pass_reasons=["All " + str(len(admin_user_ids)) + " privileged admin account(s) are mailbox-free "
                          "dedicated admin identities"],
            input_summary=summary, additional_findings=findings)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
