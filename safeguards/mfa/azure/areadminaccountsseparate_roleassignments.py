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

Privileged roles are Entra built-in role TEMPLATE ids (identical in every tenant), per
https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference .
Service-principal holders are not accounts a person signs in with and are excluded (counted in the summary).

Verdict:
  True   both feeds complete, at least one human privileged admin, and none has a mail address or an
         Exchange-bearing licence.
  False  at least one privileged human admin has a mail address or an Exchange-bearing licence.
  None   (Unevaluated, dataCollection error) a missing or error feed, a paged feed (@odata.nextLink present:
         only the first page was read), a role held by a group (members not read), a privileged user absent
         from the complete user feed, or no human privileged admin at all.
"""
import json
from datetime import datetime

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
                    input_summary=None, api_errors=None, transformation_errors=None):
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
                           "recommendations": recommendations or [], "additionalFindings": []},
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
    if feed.get("error") or feed.get("errors"):
        return None, "The " + name + " feed returned a Microsoft Graph error."
    records = feed.get("value")
    if not isinstance(records, list):
        return None, "The " + name + " feed carries no value list; nothing to evaluate."
    if not all(isinstance(r, dict) for r in records):
        return None, "The " + name + " feed is not a list of objects."
    if feed.get("@odata.nextLink"):
        return None, "The " + name + " feed is paged and only its first page was read; not evaluated."
    return records, None


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
        assignments, problem = graph_list(data.get("roleAssignments"), "roleAssignments")
        if problem:
            return unevaluated(problem, validation)
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

        admin_user_ids = []
        sp_holders = 0
        group_holders = 0
        unknown_holders = 0
        for a in assignments:
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
            else:
                unknown_holders = unknown_holders + 1

        summary = {"privilegedUserAdmins": len(admin_user_ids), "privilegedServicePrincipals": sp_holders,
                   "privilegedGroups": group_holders, "userCount": len(users)}
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
            return unevaluated("No user holds a privileged directory role; there is no admin account to judge.",
                               validation, summary)

        with_mail = []
        for pid in admin_user_ids:
            u = users_by_id[pid]
            if has_mailbox(u):
                with_mail.append(u.get("userPrincipalName") or pid)
        summary["adminsWithMailbox"] = len(with_mail)
        result = {KEY: len(with_mail) == 0, "adminCount": len(admin_user_ids), "adminsWithMailbox": len(with_mail)}
        if with_mail:
            return create_response(
                result=result, validation=validation,
                fail_reasons=[str(len(with_mail)) + " of " + str(len(admin_user_ids)) + " privileged admin account(s) "
                              "have a mailbox (mail address or Exchange licence): " + ", ".join(with_mail[:10])],
                recommendations=["Give each administrator a separate, unlicensed admin-only account and remove "
                                 "privileged roles from everyday mail-enabled accounts"],
                input_summary=summary)
        return create_response(
            result=result, validation=validation,
            pass_reasons=["All " + str(len(admin_user_ids)) + " privileged admin account(s) are mailbox-free "
                          "dedicated admin identities"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
