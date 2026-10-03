"""
Transformation: areAdminAccountsSeparate
Vendor: Microsoft (Microsoft 365 / Entra ID)
Category: Identity / Admin Accounts

Evaluates whether privileged directory roles are held by dedicated admin accounts rather
than by day-to-day accounts that have a mailbox or a productivity licence.

WHY THIS FILE WAS REWRITTEN. The previous version scored the Microsoft Secure Score
control `mdo_blockmailforward` (block mail forwarding) and reported the result as admin
account separation, so IAM-004 "Admin Account Segmentation" passed or failed on an
unrelated mail-flow setting. This file never treats Secure Score data as evidence.

WHAT "SEPARATE" MEANS HERE. Every enabled user that holds a privileged Entra directory
role (Global Administrator and the other admin roles in PRIVILEGED_ROLE_IDS) is a
dedicated admin account:

  * it has no Exchange Online mailbox: no assigned service plan is an enabled Exchange
    plan; and
  * it holds no productivity licence: no assigned SKU is a known mailbox or Office
    productivity SKU (MAILBOX_OR_PRODUCTIVITY_SKU_IDS).

A non-empty `mail` attribute ALONE (no productivity SKU and no enabled Exchange plan) is
a finding, not a fail (J.J., 3 Oct 2026). `mail` is a directory attribute that is often
set on cloud-only admin accounts for notifications or forwarding without any mailbox
behind it, so it is not shown to be a day-to-day account. It is reported under
additionalFindings and does not change the verdict, but ONLY when the mailbox question is
answered: assignedPlans is in the read and shows no enabled Exchange plan, or every assigned
SKU is known and is not a productivity SKU (KNOWN_NON_PRODUCTIVITY_SKU_IDS; no licence at all
also counts). `mail` plus a SKU we cannot classify and no assignedPlans is not evaluated
("mailbox licence could not be classified"), never a pass.

Licences that are not productivity licences (Entra ID P1/P2, for example) do not count.
Role holders that are service principals are not user accounts and are not judged.
Disabled role holders cannot sign in; they are counted but not treated as violations.

INPUT. The two Microsoft Graph reads the Azure AD One-Click workflow already makes, merged
by a two-step workflow:

    {"roleAssignments": <Graph list body>, "users": <Graph list body>}

from
    GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal($select=id)
    GET /v1.0/users?$select=id,userPrincipalName,mail,accountEnabled,assignedLicenses
        [,assignedPlans]&$top=999

`directoryRoles` (GET /v1.0/directoryRoles?$expand=members) is accepted as an alternative
role source. Both need only Directory.Read.All (or RoleManagement.Read.Directory plus
User.Read.All), which the One-Click app already holds.

FAIL CLOSED. An empty, null, unrecognised or error body (PSError, Graph {"error": {...}},
an HTTP 4xx/5xx envelope, an IS error status), a Secure Score body, a read with no
privileged role holders (every tenant has a Global Administrator), a truncated read
(@odata.nextLink) or a role holder that cannot be resolved returns
areAdminAccountsSeparate = false together with a dataCollection error, so the check reads
"not evaluated" rather than pass or fail. A role holder that is shown to have a mailbox or
a productivity licence (or an enabled Exchange plan) is a measured fail, whatever else is
missing.
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
        "transformationId": "areAdminAccountsSeparate",
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

CRITERIA_KEY = "areAdminAccountsSeparate"
SOURCE = "Microsoft Graph"
WRAPPER_KEYS = ["api_response", "apiResponse", "response", "result", "Output", "rawResponse"]
ERROR_STATUSES = ["error", "failure", "failed", "not available"]

# Entra built-in directory role TEMPLATE ids (identical in every tenant; for built-in roles
# unifiedRoleAssignment.roleDefinitionId equals the template id). Same set as
# mfa/azure/areadminaccountsseparate.py so Azure AD and Microsoft 365 give one answer for a
# tenant. Verified against GET /v1.0/directoryRoleTemplates.
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

# Commercial SKU ids that carry an Exchange Online mailbox or the Office productivity apps
# (Microsoft "product names and service plan identifiers for licensing" reference).
# NON-EXHAUSTIVE: an unlisted SKU is backstopped by the Exchange service plans in
# assignedPlans when the read carries them. `mail` alone is a finding, not a backstop.
MAILBOX_OR_PRODUCTIVITY_SKU_IDS = [
    "4b9405b0-7788-4568-add1-99614e63306e",  # EXCHANGESTANDARD (Exchange Online Plan 1)
    "19ec0d23-8335-4cbd-94ac-6050e30712fa",  # EXCHANGEENTERPRISE (Exchange Online Plan 2)
    "18181a46-0d4e-45cd-891e-60aabd171b4e",  # STANDARDPACK (Office 365 E1)
    "6fd2c87f-b296-42f0-b197-1e91e994b900",  # ENTERPRISEPACK (Office 365 E3)
    "c7df2760-2c81-4ef7-b578-5b5392b571df",  # ENTERPRISEPREMIUM (Office 365 E5)
    "4b585984-651b-448a-9e53-3b10f069cf7f",  # DESKLESSPACK (Office 365 F3)
    "05e9a617-0261-4cee-bb44-138d3ef5d965",  # SPE_E3 (Microsoft 365 E3)
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06",  # SPE_E5 (Microsoft 365 E5)
    "66b55226-6b4f-492c-910c-a3b7a3c9d993",  # SPE_F1 (Microsoft 365 F3)
    "3b555118-da6a-4418-894f-7df1e2096870",  # O365_BUSINESS_ESSENTIALS (M365 Business Basic)
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3",  # O365_BUSINESS_PREMIUM (M365 Business Standard)
    "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",  # SPB (Microsoft 365 Business Premium)
    "cdd28e44-67e3-425e-be4c-737fab2899d3",  # O365_BUSINESS (Microsoft 365 Apps for business)
    "c2273bd0-dff7-4215-9ef5-2c7bcfb06425",  # OFFICESUBSCRIPTION (Microsoft 365 Apps for enterprise)
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
                "Grant the integration Directory.Read.All (or RoleManagement.Read.Directory "
                "and User.Read.All) and re-consent the tenant")
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


def is_secure_score(body):
    """A GET /security/secureScores body: Secure Score is not evidence of admin separation."""
    body = unwrap(body)
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        rows = body["value"]
    elif isinstance(body, list):
        rows = body
    else:
        return False
    for row in rows:
        if isinstance(row, dict) and ("controlScores" in row or "currentScore" in row):
            return True
    return False


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


def has_mail_address(user):
    """A non-empty `mail` attribute: a finding on its own, never a fail by itself."""
    mail = user.get("mail")
    return bool(mail and str(mail).strip())


# Licences that are known NOT to carry a mailbox or the Office apps. Same set as
# mfa/azure/areadminaccountsseparate.py.
KNOWN_NON_PRODUCTIVITY_SKU_IDS = [
    "078d2b04-f1bd-4111-bbd4-b4b1b354cef4",  # AAD_PREMIUM (Entra ID P1)
    "84a661c4-e949-4bd2-a560-ed7766fcaf2b",  # AAD_PREMIUM_P2 (Entra ID P2)
    "efccb6f7-5641-4e0e-bd10-b4976e1bf68e",  # EMS (Enterprise Mobility + Security E3)
    "b05e124f-c7cc-45a0-a6aa-8cf78c946968",  # EMSPREMIUM (Enterprise Mobility + Security E5)
    "061f9ace-7d42-4136-88ac-31dc755f143f",  # INTUNE_A (Microsoft Intune)
]


def mail_only_is_classified(user):
    """For a role holder with `mail` and no proven mailbox licence or Exchange plan: True when
    the mailbox question is answered (assignedPlans present, or every SKU known and
    non-productivity), False when a SKU could not be classified and there is no assignedPlans."""
    if isinstance(user.get("assignedPlans"), list):
        return True
    for lic in user.get("assignedLicenses") or []:
        sku = lower_id(lic.get("skuId") if isinstance(lic, dict) else lic)
        if sku not in KNOWN_NON_PRODUCTIVITY_SKU_IDS:
            return False
    return True


def has_mailbox_or_productivity_licence(user):
    """Return the reasons this role holder is a day-to-day account (empty if none).

    Only a productivity licence or an enabled Exchange plan counts. `mail` alone does not
    (see has_mail_address)."""
    reasons = []
    for lic in user.get("assignedLicenses") or []:
        sku = lower_id(lic.get("skuId") if isinstance(lic, dict) else lic)
        if sku in MAILBOX_OR_PRODUCTIVITY_SKU_IDS:
            reasons.append("holds a mailbox/productivity licence")
            break
    for plan in user.get("assignedPlans") or []:
        if not isinstance(plan, dict):
            continue
        service = str(plan.get("service") or "").lower()
        status = str(plan.get("capabilityStatus") or "").lower()
        if service == "exchange" and status == "enabled":
            reasons.append("has an enabled Exchange Online plan")
            break
    return reasons


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
                found[lower_id(member.get("id"))] = odata_kind(member) or found.get(lower_id(member.get("id")), "")
    return found


def transform(input):
    """Evaluate whether privileged Entra roles are held by dedicated admin accounts."""
    default_result = {
        CRITERIA_KEY: False,
        "adminCount": 0,
        "adminsWithMailboxOrLicence": 0,
        "unresolvedAdminPrincipals": 0,
        "adminsWithMailAttributeOnly": 0,
    }
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result=default_result,
                validation=validation,
                fail_reasons=["Input validation failed: " + "; ".join(validation.get("errors", []))],
                recommendations=["Verify the Microsoft integration is configured correctly"],
            )

        if is_secure_score(data):
            return create_response(
                result=default_result,
                validation=validation,
                api_errors=[
                    "Input is Microsoft Secure Score data, which does not show who holds admin "
                    "roles; admin account separation needs role assignments and user licences"
                ],
                fail_reasons=["No evidence about admin account separation was received"],
                recommendations=[
                    "Wire areAdminAccountsSeparate to the Graph roleAssignments and users "
                    "(with assignedLicenses) methods"
                ],
            )

        assignments, directory_roles, users, api_errors, recommendations, truncated = collect(data)

        if (assignments is None and directory_roles is None) or users is None:
            if not api_errors:
                api_errors.append(
                    "Input carries no Microsoft Graph role assignment and user licence data"
                )
                recommendations.append(
                    "Wire areAdminAccountsSeparate to the Graph roleAssignments and users "
                    "(with assignedLicenses) methods"
                )
            return create_response(
                result=default_result,
                validation=validation,
                api_errors=api_errors,
                fail_reasons=["Could not retrieve role assignments and user licences from Microsoft Graph"],
                recommendations=recommendations,
            )

        users_by_id = {}
        has_licence_field = False
        for user in users:
            if isinstance(user, dict) and lower_id(user.get("id")):
                users_by_id[lower_id(user.get("id"))] = user
                if "assignedLicenses" in user:
                    has_licence_field = True

        principals = privileged_principals(assignments, directory_roles)

        admin_count = 0
        disabled_admins = 0
        service_principals = 0
        unresolved = []
        violations = []
        mail_only = []
        unclassified = []
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
            admin_count = admin_count + 1
            if not is_enabled(user):
                disabled_admins = disabled_admins + 1
                continue
            reasons = has_mailbox_or_productivity_licence(user)
            name = short(user.get("userPrincipalName") or user.get("displayName") or pid)
            if reasons:
                if has_mail_address(user):
                    reasons = ["has a mail address"] + reasons
                violations.append(name + ": " + ", ".join(reasons))
            elif has_mail_address(user):
                if mail_only_is_classified(user):
                    mail_only.append(name)
                else:
                    unclassified.append(name)

        result = {
            CRITERIA_KEY: False,
            "adminCount": admin_count,
            "adminsWithMailboxOrLicence": len(violations),
            "unresolvedAdminPrincipals": len(unresolved),
            "adminsWithMailAttributeOnly": len(mail_only),
            "adminsWithUnclassifiedMailboxLicence": len(unclassified),
        }
        summary = {
            "privilegedPrincipals": len(principals),
            "adminUsers": admin_count,
            "disabledAdminUsers": disabled_admins,
            "servicePrincipalAdmins": service_principals,
            "userCount": len(users_by_id),
            "hasLicenceData": has_licence_field,
            "truncated": truncated,
        }
        findings = []
        if service_principals > 0:
            findings.append(f"{service_principals} privileged role holder(s) are service principals (not judged)")
        if disabled_admins > 0:
            findings.append(f"{disabled_admins} privileged role holder(s) are disabled accounts (not judged)")
        if mail_only:
            findings.append(
                f"{len(mail_only)} privileged admin account(s) have a mail address but no productivity "
                f"licence and no enabled Exchange plan (a finding, not a fail): " + "; ".join(mail_only[:5])
            )

        if len(violations) > 0:
            # A proven mailbox/productivity licence on ANY admin is a measured fail, whatever else
            # is unresolved; the unresolved admins are named in the reason.
            fail_reason = (f"{len(violations)} of {admin_count} privileged admin account(s) are day-to-day "
                           f"accounts with a mailbox or productivity licence: " + "; ".join(violations[:5]))
            if unresolved or unclassified:
                fail_reason += "; also unresolved: " + "; ".join((unresolved + unclassified)[:5])
            return create_response(
                result=result,
                validation=validation,
                fail_reasons=[fail_reason],
                recommendations=[
                    "Give each administrator a separate cloud-only admin account with no mailbox and "
                    "no productivity licence, and remove admin roles from everyday accounts"
                ],
                input_summary=summary,
                additional_findings=findings,
            )

        incomplete = []
        if not has_licence_field and len(users_by_id) > 0:
            incomplete.append("the user read carries no assignedLicenses field")
        if truncated:
            incomplete.append("the read is truncated (@odata.nextLink on " + ", ".join(truncated) + ")")
        if unresolved:
            incomplete.append(f"{len(unresolved)} privileged role holder(s) could not be resolved: "
                              + "; ".join(unresolved[:5]))
        if unclassified:
            incomplete.append(f"Mailbox licence could not be classified for {len(unclassified)} privileged admin "
                              f"account(s) with a mail address and no assignedPlans in the read: "
                              + "; ".join(unclassified[:5]))
        if admin_count == 0 and not unresolved:
            incomplete.append("no enabled user holds a privileged directory role; every tenant has a "
                              "Global Administrator, so the read is incomplete")
        if api_errors:
            incomplete = api_errors + incomplete

        if incomplete:
            return create_response(
                result=result,
                validation=validation,
                api_errors=incomplete,
                fail_reasons=["Admin account separation could not be confirmed from a complete read"],
                recommendations=recommendations + [
                    "Read all role assignments and all users with assignedLicenses ($top=999, follow nextLink)"
                ],
                input_summary=summary,
                additional_findings=findings,
            )

        result[CRITERIA_KEY] = True
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=[
                f"All {admin_count} privileged admin account(s) are dedicated: no enabled Exchange "
                f"plan and no mailbox/productivity licence"
            ],
            input_summary=summary,
            additional_findings=findings,
        )

    except Exception as e:
        return create_response(
            result=default_result,
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"],
        )
