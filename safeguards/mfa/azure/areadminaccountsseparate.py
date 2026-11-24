"""
Transformation: areAdminAccountsSeparate
Vendor: Microsoft
Category: Identity / Admin Accounts

Evaluates whether privileged admin identities are separate from everyday mail-licensed user accounts.

A privileged role holder FAILS only on a mailbox/productivity licence (MAIL_EXCHANGE_SKU_IDS)
or an enabled Exchange plan in assignedPlans. A non-empty `mail` attribute alone is a finding,
not a fail (J.J., 3 Oct 2026; same rule as the Microsoft 365 file
874a78ff-.../areadminaccountsseparate.py), but only when the mailbox question is answered:
assignedPlans is in the read and shows no enabled Exchange plan, or every assigned SKU is known
and is not a productivity SKU (KNOWN_NON_PRODUCTIVITY_SKU_IDS). `mail` plus a SKU we cannot
classify and no assignedPlans is not evaluated ("mailbox licence could not be classified"),
never a pass. A proven fail on any admin wins over unresolved admins. No role or licence data
is not evaluated, never a measured fail. So is a partial read: a page with an @odata.nextLink
(role assignments, directory roles, their members or users) cannot show that no other admin
holds a mailbox, and an administrator whose own row has no assignedLicenses list (missing or
null) was never checked for a licence. Neither can read as a pass.

PIM-eligible admins: roleAssignments holds ACTIVE assignments only. When the workflow also merges
"roleEligibilityScheduleInstances" (GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances,
every page read), the principals of the instances in effect now that hold a PRIVILEGED_ROLE_IDS role join
the admin population, and the result reports activeAdminCount and eligibleAdminCount (a holder of both is in
both; adminCount is the distinct total). An eligible group, like an active one, is not in the user feed and
stays unresolved. Without that key the verdict is what it was and eligibleAssignmentsRead is false; with the
key present but not read whole (an error or vendor error as data, an @odata.nextLink) the read is partial,
exactly like a truncated role-assignment read.
"""

import json
from datetime import datetime, timezone


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


# The validator's text can carry vendor text, so what is echoed under additionalInfo.validation is
# bounded: at most MAX_ECHOED_ITEMS strings of at most MAX_ECHOED_TEXT characters each.
MAX_ECHOED_ITEMS = 20
MAX_ECHOED_TEXT = 300


def bounded_texts(items):
    """A list of at most MAX_ECHOED_ITEMS strings, each cut to MAX_ECHOED_TEXT characters."""
    if not items:
        return []
    if not isinstance(items, list):
        items = [items]
    bounded = []
    for item in items[:MAX_ECHOED_ITEMS]:
        text = str(item)
        if len(text) > MAX_ECHOED_TEXT:
            text = text[:MAX_ECHOED_TEXT] + "..."
        bounded.append(text)
    return bounded


def bounded_code(value):
    """An error code from a Graph error body, as text of at most 80 characters (None stays None)."""
    if value is None:
        return None
    return str(value)[:80]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    validation_status = validation.get("status", "unknown")
    if isinstance(validation_status, str):
        validation_status = validation_status[:40]
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation_status,
                "errors": bounded_texts(validation.get("errors")),
                "warnings": bounded_texts(validation.get("warnings"))
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
                "transformationId": "areAdminAccountsSeparate",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


# Entra built-in directory role TEMPLATE ids (identical in every tenant). Verified against
# GET /v1.0/directoryRoleTemplates - do not add ids that have not been checked against that list.
PRIVILEGED_ROLE_IDS = {
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
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451",  # Global Reader (read-only but tenant-wide - conservative inclusion)
}

# Commercial SKU ids that carry an Exchange Online mailbox or the Office productivity apps
# (Microsoft "product names and service plan identifiers for licensing" reference). Same set
# as the Microsoft 365 file 874a78ff-.../areadminaccountsseparate.py so both give one answer
# for a tenant. NON-EXHAUSTIVE: an unlisted SKU is backstopped by the Exchange service plans
# in assignedPlans when the read carries them. `mail` alone is a finding, not a backstop.
MAIL_EXCHANGE_SKU_IDS = {
    "4b9405b0-7788-4568-add1-99614e63306e",  # EXCHANGESTANDARD (Exchange Online Plan 1)
    "19ec0d23-8335-4cbd-94ac-6050e30712fa",  # EXCHANGEENTERPRISE (Exchange Online Plan 2)
    "efb87545-963c-4f51-83ff-779edf226046",  # EXCHANGE_S_ENTERPRISE (Plan 2 service plan id; kept)
    "18181a46-0d4e-45cd-891e-60aabd171b4e",  # STANDARDPACK (Office 365 E1)
    "6fd2c87f-b296-42f0-b197-1e91e994b900",  # ENTERPRISEPACK (Office 365 E3)
    "c7df2760-2c81-4ef7-b578-5b5392b571df",  # ENTERPRISEPREMIUM (Office 365 E5)
    "4b585984-651b-448a-9e53-3b10f069cf7f",  # DESKLESSPACK (Office 365 F3)
    "05e9a617-0261-4cee-bb44-138d3ef5d965",  # SPE_E3 (Microsoft 365 E3)
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06",  # SPE_E5 (Microsoft 365 E5)
    "66b55226-6b4f-492c-910c-a3b7a3c9d993",  # SPE_F1 (Microsoft 365 F3)
    "3b555118-da6a-4418-894f-7df1e2096870",  # O365_BUSINESS_ESSENTIALS (M365 Business Basic)
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3",  # O365_BUSINESS_PREMIUM (M365 Business Standard; lab-verified)
    "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",  # SPB (Microsoft 365 Business Premium)
    "cdd28e44-67e3-425e-be4c-737fab2899d3",  # O365_BUSINESS (Microsoft 365 Apps for business)
    "c2273bd0-dff7-4215-9ef5-2c7bcfb06425",  # OFFICESUBSCRIPTION (Microsoft 365 Apps for enterprise)
}


def account_ref(pid):
    """A partial object id for reasons: enough to find the account in Entra, no personal data (C4)."""
    return "user " + str(pid)[:8] + "..."


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and "value" in value:
        nested = value.get("value")
        if isinstance(nested, list):
            return nested
        return [nested] if nested else []
    return [value]


def has_next_link(value):
    return isinstance(value, dict) and bool(value.get("@odata.nextLink"))


def truncated_parts(data):
    """Names of the parts of the read that Graph says continue on another page (@odata.nextLink)."""
    parts = []
    if has_next_link(data):
        parts.append("the user feed")
    for label in ["roleAssignments", "directoryRoles", "users"]:
        if has_next_link(data.get(label)):
            parts.append(label)
    for role in as_list(data.get("directoryRoles")):
        if isinstance(role, dict) and has_next_link(role.get("members")):
            parts.append("directoryRoles members")
            break
    return parts


def role_id_from_entry(entry):
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return None
    return entry.get("roleDefinitionId") or entry.get("roleTemplateId") or entry.get("roleId")


def directory_role_template_id(role):
    if isinstance(role, str):
        return role
    if not isinstance(role, dict):
        return None
    return role.get("roleTemplateId") or role.get("roleDefinitionId")


def principal_id_from_entry(entry):
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return None
    return entry.get("principalId") or entry.get("id") or entry.get("userId")


def collect_admin_principal_ids(data, users):
    admin_ids = set()

    for assignment in as_list(data.get("roleAssignments")):
        role_id = role_id_from_entry(assignment)
        principal_id = principal_id_from_entry(assignment)
        if role_id in PRIVILEGED_ROLE_IDS and principal_id:
            admin_ids.add(principal_id)

    for role in as_list(data.get("directoryRoles")):
        role_id = directory_role_template_id(role)
        if role_id not in PRIVILEGED_ROLE_IDS:
            continue
        if not isinstance(role, dict):
            continue
        for member in as_list(role.get("members")):
            principal_id = principal_id_from_entry(member)
            if principal_id:
                admin_ids.add(principal_id)

    for user in users:
        if not isinstance(user, dict):
            continue
        user_id = user.get("id")
        for role_entry in as_list(user.get("assignedRoles") or user.get("directoryRoleIds")):
            role_id = role_id_from_entry(role_entry)
            if role_id in PRIVILEGED_ROLE_IDS and user_id:
                admin_ids.add(user_id)

    return admin_ids


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


def truncation_flag(obj):
    """The truncation marker set on obj, '' when none: an @odata.nextLink or _links.next href still set, or
    paginationTruncated / truncated / iterateTruncated on the object itself or under its response_metadata,
    metadata or pagination block (the markers Integration-Service and the workflow engine use for a cut-off read)."""
    if not isinstance(obj, dict):
        return ""
    if str(obj.get("@odata.nextLink") or "").strip() not in ("", "None", "null"):
        return "@odata.nextLink"
    links = obj.get("_links")
    if isinstance(links, dict) and isinstance(links.get("next"), dict):
        if str(links.get("next").get("href") or "").strip() not in ("", "None", "null"):
            return "_links.next"
    blocks = [("", obj)]
    for k in ("response_metadata", "metadata", "pagination"):
        if isinstance(obj.get(k), dict):
            blocks.append((k + ".", obj.get(k)))
    for prefix, block in blocks:
        for k in ("paginationTruncated", "truncated", "iterateTruncated"):
            value = block.get(k)
            if value is True or str(value).strip().lower() in ("true", "1"):
                return prefix + k
    return ""


def cut_text(flag):
    """'only part of it was read (...)' for a truncation marker from truncation_flag."""
    if flag in ("@odata.nextLink", "_links.next"):
        return "only part of it was read (" + flag + " remains)"
    return "only part of it was read (" + flag + " is set)"


def graph_page_problem(page):
    """Why one Graph list page is not readable evidence (an error, a refusal, no value list), '' when it is."""
    if not isinstance(page, dict):
        return "the body is not an object"
    if "vendorErrorAsResponse" in page:
        return "Microsoft Graph refused the read (vendor error returned as data)"
    if page.get("error") or "PSError" in page:
        return "Microsoft Graph returned an error"
    for k in ("statusCode", "status_code"):
        code = page.get(k)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Microsoft Graph answered HTTP " + str(code)
    if str(page.get("status") or "").strip().lower() in ("error", "failure", "failed", "not available"):
        return "the read reported an error status"
    if not isinstance(page.get("value"), list):
        return "the body carries no value list"
    return ""


def eligibility_page_problem(page):
    """Why one page of the eligibility read is not evidence, '' when it is."""
    problem = graph_page_problem(page)
    if problem:
        return problem
    flag = truncation_flag(page)
    if flag:
        return cut_text(flag)
    for row in page.get("value"):
        if not isinstance(row, dict) or not str(row.get("principalId") or "").strip():
            return "an instance is not an object with a principalId"
    return ""


def eligibility_rows(data, now):
    """(rows, problem, ended) for the PIM eligibility read.
    Absent: (None, '', 0). Present but not read whole: (None, problem, 0). Read whole: the instances in effect at
    `now`, and how many were left out because they had ended or not yet begun. A truncation marker on the body, on
    any wrapper around it, or under paginationStats.roleEligibilityScheduleInstances makes the read incomplete:
    eligible admins were not fully read, so the result can never pass on them."""
    if not isinstance(data, dict) or ELIGIBLE_KEY not in data:
        return None, "", 0
    incomplete = ("the PIM role eligibility read (" + ELIGIBLE_ENDPOINT + ") is incomplete, so eligible admins "
                  "were not fully read: ")
    body = data.get(ELIGIBLE_KEY)
    flag = truncation_flag(body)
    stats = data.get("paginationStats")
    if not flag and isinstance(stats, dict) and truncation_flag(stats.get(ELIGIBLE_KEY)):
        flag = "paginationStats." + ELIGIBLE_KEY + "." + truncation_flag(stats.get(ELIGIBLE_KEY))
    for attempt in range(4):
        if not isinstance(body, dict) or "value" in body:
            break
        moved = False
        for k in ELIGIBLE_WRAPPERS:
            if isinstance(body.get(k), (dict, list)):
                body = body[k]
                moved = True
                break
        if not moved:
            break
        if not flag:
            flag = truncation_flag(body)
    if flag:
        return None, incomplete + cut_text(flag), 0
    if isinstance(body, list) and len(body) > 0 and all(
            isinstance(p, dict) and ("value" in p or "error" in p or "vendorErrorAsResponse" in p) for p in body):
        pages = body
    elif isinstance(body, list):
        pages = [{"value": body}]
    else:
        pages = [body]
    rows = []
    ended = 0
    for page in pages:
        problem = eligibility_page_problem(page)
        if problem:
            return None, incomplete + problem, 0
        for row in page.get("value"):
            if eligibility_in_effect(row, now):
                rows.append(row)
            else:
                ended = ended + 1
    return rows, "", ended


# ----------------------------------------------------------------------------- ACTIVE role assignment read
# PIM-eligible holders only ADD to an active population that was read. When the active read (roleAssignments) is
# missing, an error, refused, or not a list of assignments naming their principal, eligibility data never stands
# in for it: the result is not evaluated.
ACTIVE_ENDPOINT = "GET /v1.0/roleManagement/directory/roleAssignments"
PAGE_MARKERS = ("value", "error", "vendorErrorAsResponse", "PSError")


def active_assignment_rows(body):
    """(rows, problem, flag) for the ACTIVE role assignment read: a Graph list body, a bare list of assignments or
    a list of Graph pages, under any engine wrapper. problem is set when the read is missing, an error, refused, or
    holds a row that is not an assignment naming its principal; flag names a truncation marker (an unread next
    page) for the caller to report as a truncated read."""
    prefix = "the active role assignment read (" + ACTIVE_ENDPOINT + ") "
    if body is None:
        return None, prefix + "is missing; PIM-eligible holders never stand in for the active admins", ""
    flag = truncation_flag(body)
    for attempt in range(4):
        if not isinstance(body, dict) or "value" in body:
            break
        moved = False
        for k in ELIGIBLE_WRAPPERS:
            if isinstance(body.get(k), (dict, list)):
                body = body[k]
                moved = True
                break
        if not moved:
            break
        if not flag:
            flag = truncation_flag(body)
    paged = isinstance(body, list) and len(
        [p for p in body if isinstance(p, dict) and len([k for k in PAGE_MARKERS if k in p]) > 0]) > 0
    if paged:
        pages = body
    elif isinstance(body, list):
        pages = [{"value": body}]
    else:
        pages = [body]
    rows = []
    for page in pages:
        problem = graph_page_problem(page)
        if problem:
            return None, prefix + "cannot be read: " + problem, flag
        if not flag:
            flag = truncation_flag(page)
        for row in page.get("value"):
            principal = {}
            if isinstance(row, dict) and isinstance(row.get("principal"), dict):
                principal = row.get("principal")
            if not isinstance(row, dict) or not str(row.get("principalId") or principal.get("id") or "").strip():
                return None, prefix + "cannot be read: an assignment is not an object naming its principal", flag
            rows.append(row)
    return rows, "", flag


def active_list_read(value):
    """True for a role-assignment read that is a list body (empty or not) with no error."""
    if isinstance(value, list):
        return True
    return isinstance(value, dict) and isinstance(value.get("value"), list) and not value.get("error")


def eligible_admin_principal_ids(rows):
    """Principal ids of the PIM-eligible instances (in effect now) of privileged roles."""
    admin_ids = set()
    for row in rows or []:
        role_id = role_id_from_entry(row)
        principal_id = principal_id_from_entry(row)
        if role_id in PRIVILEGED_ROLE_IDS and principal_id:
            admin_ids.add(principal_id)
    return admin_ids


def user_has_mail_or_exchange_license(user):
    """True only for a mailbox/productivity SKU or an enabled Exchange plan. `mail` alone is
    not enough (J.J., 3 Oct 2026): see user_has_mail_attribute."""
    licenses = user.get("assignedLicenses") or []
    for lic in licenses:
        if not isinstance(lic, dict):
            continue
        sku_id = lic.get("skuId")
        if sku_id and str(sku_id).lower() in MAIL_EXCHANGE_SKU_IDS:
            return True
    for plan in user.get("assignedPlans") or []:
        if not isinstance(plan, dict):
            continue
        service = str(plan.get("service") or "").lower()
        status = str(plan.get("capabilityStatus") or "").lower()
        if service == "exchange" and status == "enabled":
            return True
    return False


# Licences that are known NOT to carry a mailbox or the Office apps. Same set as the
# Microsoft 365 file. An admin whose `mail` is set and whose SKUs are all here (or who has no
# licence at all) is a finding, not a fail; any other SKU with no assignedPlans is unclassified.
KNOWN_NON_PRODUCTIVITY_SKU_IDS = {
    "078d2b04-f1bd-4111-bbd4-b4b1b354cef4",  # AAD_PREMIUM (Entra ID P1)
    "84a661c4-e949-4bd2-a560-ed7766fcaf2b",  # AAD_PREMIUM_P2 (Entra ID P2)
    "efccb6f7-5641-4e0e-bd10-b4976e1bf68e",  # EMS (Enterprise Mobility + Security E3)
    "b05e124f-c7cc-45a0-a6aa-8cf78c946968",  # EMSPREMIUM (Enterprise Mobility + Security E5)
    "061f9ace-7d42-4136-88ac-31dc755f143f",  # INTUNE_A (Microsoft Intune)
}


def mail_only_is_classified(user):
    """For a role holder with `mail` and no proven mailbox licence or Exchange plan: True when
    the mailbox question is answered (assignedPlans present, or every SKU known and
    non-productivity), False when a SKU could not be classified and there is no assignedPlans."""
    if isinstance(user.get("assignedPlans"), list):
        return True
    for lic in user.get("assignedLicenses") or []:
        sku_id = lic.get("skuId") if isinstance(lic, dict) else lic
        if str(sku_id or "").strip().lower() not in KNOWN_NON_PRODUCTIVITY_SKU_IDS:
            return False
    return True


def user_has_mail_attribute(user):
    """A non-empty `mail` attribute: a finding on its own, never a fail by itself."""
    mail = user.get("mail")
    return bool(mail and str(mail).strip())


# #101: findings name the affected accounts (same shape as legacyauthblocked.py). The first reason names
# at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with
# the full count in affectedAccountCount. The verdict never reads them.
MAX_NAMED = 20
MAX_AFFECTED = 50


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def affected_line(scope, affected, total, what):
    """One line naming the tool and its scope: 'Microsoft Entra ID (<scope>): N of M <what>: a, b and K more'."""
    return "Microsoft Entra ID (%s): %d of %d %s: %s" % (scope, len(affected), total, what, name_list(affected))


def with_affected(summary, affected):
    summary["affectedAccounts"] = affected[:MAX_AFFECTED]
    summary["affectedAccountCount"] = len(affected)
    return summary


def transform(input):
    # FEED CAVEAT: the integration's stated intent ("admins hold no mail/Exchange license")
    # needs role membership + assignedLicenses, but the current getUsers feed is a bare
    # GET /v1.0/users that carries neither. Until the feed is upgraded, this transform reads
    # not evaluated with an explicit feed-update reason rather than pretending to evaluate (no
    # name-pattern heuristics, and never a measured fail on missing data). The rich branch below activates automatically once the feed carries
    # role data (directoryRoles/roleAssignments/assignedRoles) AND assignedLicenses.
    criteriaKey = "areAdminAccountsSeparate"
    feed_update_reason = (
        "User feed does not include role/license data required to evaluate admin account "
        "separation - integration feed update required"
    )
    feed_update_recommendation = (
        "Upgrade the getUsers feed to include assignedLicenses on user objects and "
        "privileged directory role membership (e.g. directoryRoles or roleAssignments)"
    )
    default_result = {
        criteriaKey: False,
        "userCount": 0,
        "adminCount": 0,
        "adminsWithMailLicense": 0,
        "adminsWithMailAttributeOnly": 0,
    }

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return create_response(
                result=default_result,
                validation=validation,
                api_errors=["Unexpected input format: expected a JSON object with Microsoft Graph users"]
            )

        if validation.get("status") == "failed":
            # Input that failed validation is not a measurement of the tenant: carry it as a data
            # collection error so the check reads "not evaluated", never a measured fail.
            return create_response(
                result=default_result,
                validation=validation,
                api_errors=["Input validation failed"],
                fail_reasons=["Input validation failed"]
            )

        if "error" in data:
            error_info = data.get("error", {})
            if not isinstance(error_info, dict):
                error_info = {"message": str(error_info)[:200]}
            inner_error = error_info.get("innerError", {})
            if not isinstance(inner_error, dict):
                inner_error = {}
            error_message = error_info.get("message")
            error_message = str(error_message)[:200] if error_message else "API error"
            return create_response(
                result=default_result,
                validation={"status": "error", "errors": [error_message], "warnings": []},
                api_errors=[f"Microsoft Graph API error: {str(error_info.get('code', 'unknown'))[:80]}"],
                input_summary={"errorCode": bounded_code(error_info.get("code")),
                               "innerErrorCode": bounded_code(inner_error.get("code")) if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        no_evidence = []
        findings = []

        # getUsers puts the users at "value"; a workflow that merges role assignments with
        # users (Azure AD One-Click: output keys roleAssignments + users) puts them at "users".
        users = data.get("value") or as_list(data.get("users")) or []
        if not isinstance(users, list):
            users = [users] if users else []

        user_count = len(users)
        users_by_id = {user.get("id"): user for user in users if isinstance(user, dict) and user.get("id")}

        has_license_data = any(isinstance(user, dict) and "assignedLicenses" in user for user in users)
        # The ACTIVE role assignment read must be readable before PIM-eligible holders are added to it. A
        # roleAssignments body that is an error, a refusal, {} or an unreadable page list is not evaluated, and
        # an eligibility list never stands in for a missing active read.
        active_problem = ""
        active_flag = ""
        if data.get("roleAssignments") is not None:
            active_rows, active_problem, active_flag = active_assignment_rows(data.get("roleAssignments"))
            if active_rows is not None:
                data = dict(data)
                data["roleAssignments"] = {"value": active_rows}
        elif ELIGIBLE_KEY in data and not as_list(data.get("directoryRoles")) and not any(
                isinstance(user, dict) and (user.get("assignedRoles") or user.get("directoryRoleIds"))
                for user in users):
            active_problem = active_assignment_rows(None)[1]
        truncated = truncated_parts(data)
        if active_flag and "roleAssignments" not in truncated:
            truncated.append("roleAssignments")
        active_principal_ids = collect_admin_principal_ids(data, users)
        eligible_rows, eligible_problem, eligible_ended = eligibility_rows(data, datetime.now(timezone.utc))
        eligible_read = eligible_rows is not None
        eligible_principal_ids = eligible_admin_principal_ids(eligible_rows)
        admin_principal_ids = set(active_principal_ids)
        for principal_id in eligible_principal_ids:
            admin_principal_ids.add(principal_id)
        # Eligible holders count as role data only beside an active role read (even an empty one): an eligible
        # list on its own is not the whole admin population.
        has_role_data = (
            bool(as_list(data.get("directoryRoles")))
            or bool(as_list(data.get("roleAssignments")))
            or len(active_principal_ids) > 0
            or (len(eligible_principal_ids) > 0 and active_list_read(data.get("roleAssignments")))
        )
        if active_problem:
            result = dict(default_result)
            result["userCount"] = user_count
            return create_response(
                result=result,
                validation=validation,
                api_errors=[active_problem],
                fail_reasons=[active_problem],
                recommendations=["Grant RoleManagement.Read.Directory and merge every page of " + ACTIVE_ENDPOINT
                                 + " under roleAssignments"],
                input_summary={"userCount": user_count, "hasLicenseData": has_license_data,
                               "activeAssignmentsRead": False, "eligibleAssignmentsRead": eligible_read},
            )

        admin_count = 0
        admins_with_mail_license = 0
        admins_with_mail_license_names = []
        admins_with_mail_attribute_only = []
        admins_unclassified = []
        admins_licence_unread = []
        admins_missing_from_user_feed = 0
        is_separate = False

        if has_license_data and has_role_data:
            for principal_id in sorted(admin_principal_ids, key=str):
                admin_count += 1
                user = users_by_id.get(principal_id)
                if user is None:
                    admins_missing_from_user_feed += 1
                    continue
                name = account_ref(principal_id)  # C4: no user principal name or display name in a reason
                if user_has_mail_or_exchange_license(user):
                    admins_with_mail_license += 1
                    admins_with_mail_license_names.append(name)
                elif not isinstance(user.get("assignedLicenses"), list):
                    # This administrator's own row carries no licence list (missing or null), so the
                    # licence question was never asked of them: not a clean row, whatever other rows hold.
                    admins_licence_unread.append(name)
                elif user_has_mail_attribute(user):
                    if mail_only_is_classified(user):
                        admins_with_mail_attribute_only.append(name)
                    else:
                        admins_unclassified.append(name)

            unresolved = []
            if admins_missing_from_user_feed > 0:
                unresolved.append(
                    f"{admins_missing_from_user_feed} privileged admin account(s) are not present in the user feed"
                )
            if admins_unclassified:
                unresolved.append(
                    f"{len(admins_unclassified)} privileged admin account(s) have a mail address and a mailbox "
                    f"licence that could not be classified (no assignedPlans in the read): "
                    + "; ".join(admins_unclassified[:5])
                )
            if admins_licence_unread:
                unresolved.append(
                    f"{len(admins_licence_unread)} privileged admin account(s) have no assignedLicenses list in the "
                    f"read, so their licences were not checked: " + "; ".join(admins_licence_unread[:5])
                )
            if truncated:
                unresolved.append(
                    "the read is truncated (@odata.nextLink on " + ", ".join(truncated) + "), so later pages "
                    "were not read"
                )
            if eligible_problem:
                unresolved.append(eligible_problem)

            is_separate = admin_count > 0 and admins_with_mail_license == 0 and not unresolved

            if admins_with_mail_license > 0:
                # A proven mailbox/productivity licence on ANY admin is a measured fail, whatever
                # else is unresolved; the unresolved admins are named in the reason.
                reason = (f"{admins_with_mail_license} of {admin_count} admin account(s) have mail/Exchange "
                          f"Online licenses; "
                          + affected_line("privileged directory roles", admins_with_mail_license_names, admin_count,
                                          "admin accounts hold a mailbox or productivity licence"))
                if unresolved:
                    reason += "; also unresolved: " + "; ".join(unresolved)
                fail_reasons.append(reason)
                recommendations.append("Use dedicated admin accounts without mail or Exchange Online licenses")
            elif is_separate:
                pass_reasons.append(
                    f"All {admin_count} privileged admin account(s) are free of mail/Exchange Online licenses"
                )
            elif admin_count == 0:
                no_evidence.append("No privileged directory role members found in user feed"
                                   + ("" if eligible_read else " (PIM-eligible assignments were not read)"))
                no_evidence.extend(unresolved)
                recommendations.append("Verify directory role membership is included in the integration feed")
            else:
                if admins_unclassified:
                    no_evidence.append("Mailbox licence could not be classified")
                no_evidence.extend(unresolved)
                recommendations.append(
                    "Include privileged role members in the getUsers feed with assignedLicenses and assignedPlans "
                    "for license evaluation"
                )
            if not eligible_read and not eligible_problem:
                findings.append(ELIGIBLE_NOT_READ)
            if admins_with_mail_attribute_only:
                findings.append(
                    f"{len(admins_with_mail_attribute_only)} privileged admin account(s) have a mail address but "
                    f"no productivity licence and no enabled Exchange plan (a finding, not a fail): "
                    + "; ".join(admins_with_mail_attribute_only[:5])
                )
        else:
            # No role or licence data is no evidence: not evaluated, never a measured fail
            # (2026-10-03 fleet check: 3 Azure AD passports showed FAIL on this branch).
            no_evidence.append(feed_update_reason)
            if eligible_problem:
                no_evidence.append(eligible_problem)
            recommendations.append(feed_update_recommendation)

        result = {
            criteriaKey: is_separate,
            "userCount": user_count,
            "adminCount": admin_count,
            "adminsWithMailLicense": admins_with_mail_license,
            "adminsWithMailAttributeOnly": len(admins_with_mail_attribute_only),
        }
        summary = {"userCount": user_count, "hasLicenseData": has_license_data, "hasRoleData": has_role_data,
                   "truncated": truncated, "adminsWithoutLicenceList": len(admins_licence_unread)}
        if has_license_data and has_role_data:
            # Counted over the same principals as adminCount; a holder of both kinds is in both counts.
            result["activeAdminCount"] = len(active_principal_ids)
            result["eligibleAdminCount"] = len(eligible_principal_ids) if eligible_read else None
            result["eligibleAssignmentsRead"] = eligible_read
            summary["eligibleOnlyAdminPrincipals"] = len(
                [p for p in eligible_principal_ids if p not in active_principal_ids])
            summary["eligibleAssignmentsRead"] = eligible_read
            summary["eligibleInstancesNotInEffect"] = eligible_ended

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=with_affected(summary, admins_with_mail_license_names),
            api_errors=no_evidence,
            additional_findings=findings,
        )

    except Exception as e:
        # An exception means the body was not understood, not that admins are shared: report it as a
        # data collection error too, so the check reads "not evaluated" and never a measured fail.
        error_message = str(e)[:200]
        return create_response(
            result=default_result,
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[error_message],
            api_errors=["Transformation error: " + error_message],
            fail_reasons=["Transformation error: " + error_message]
        )
