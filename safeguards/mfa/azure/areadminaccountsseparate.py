"""
Transformation: areAdminAccountsSeparate
Vendor: Microsoft
Category: Identity / Admin Accounts

Evaluates whether privileged admin identities are separate from everyday mail-licensed user accounts.
"""

import json
from datetime import datetime


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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
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

# Commercial SKU ids that include an Exchange Online mailbox (Microsoft licensing reference).
# NON-EXHAUSTIVE by design: unknown SKUs are backstopped by the mail-attribute check below.
# Complete this list against Microsoft's product-names-and-service-plan-identifiers CSV when
# the getUsers feed is upgraded to carry assignedLicenses.
MAIL_EXCHANGE_SKU_IDS = {
    "4b9405b0-7788-4568-add1-99614e63306e",  # EXCHANGESTANDARD (Exchange Online Plan 1)
    "efb87545-963c-4f51-83ff-779edf226046",  # EXCHANGEENTERPRISE (Exchange Online Plan 2)
    "6fd2c87f-b296-42f0-b197-1e91e994b900",  # ENTERPRISEPACK (Office 365 E3)
    "c7df2760-2c81-4ef7-b578-5b5392b571df",  # ENTERPRISEPREMIUM (Office 365 E5)
    "05e9a617-0261-4cee-bb44-138d3ef5d965",  # SPE_E3 (Microsoft 365 E3)
    "06ebc4ee-1bb5-47dd-8120-11324bc54e06",  # SPE_E5 (Microsoft 365 E5)
    "3b555118-da6a-4418-894f-7df1e2096870",  # O365_BUSINESS_ESSENTIALS (M365 Business Basic)
    "f245ecc8-75af-4f8e-b61f-27d8114de5f3",  # O365_BUSINESS_PREMIUM (M365 Business Standard; lab-verified)
    "cbdc14ab-d96c-4c30-b9f4-6ada7cdc1d46",  # SPB (Microsoft 365 Business Premium)
}


def _as_list(value):
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


def _role_id_from_entry(entry):
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return None
    return entry.get("roleDefinitionId") or entry.get("roleTemplateId") or entry.get("roleId")


def _directory_role_template_id(role):
    if isinstance(role, str):
        return role
    if not isinstance(role, dict):
        return None
    return role.get("roleTemplateId") or role.get("roleDefinitionId")


def _principal_id_from_entry(entry):
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return None
    return entry.get("principalId") or entry.get("id") or entry.get("userId")


def _collect_admin_principal_ids(data, users):
    admin_ids = set()

    for assignment in _as_list(data.get("roleAssignments")):
        role_id = _role_id_from_entry(assignment)
        principal_id = _principal_id_from_entry(assignment)
        if role_id in PRIVILEGED_ROLE_IDS and principal_id:
            admin_ids.add(principal_id)

    for role in _as_list(data.get("directoryRoles")):
        role_id = _directory_role_template_id(role)
        if role_id not in PRIVILEGED_ROLE_IDS:
            continue
        if not isinstance(role, dict):
            continue
        for member in _as_list(role.get("members")):
            principal_id = _principal_id_from_entry(member)
            if principal_id:
                admin_ids.add(principal_id)

    for user in users:
        if not isinstance(user, dict):
            continue
        user_id = user.get("id")
        for role_entry in _as_list(user.get("assignedRoles") or user.get("directoryRoleIds")):
            role_id = _role_id_from_entry(role_entry)
            if role_id in PRIVILEGED_ROLE_IDS and user_id:
                admin_ids.add(user_id)

    return admin_ids


def _user_has_mail_or_exchange_license(user):
    licenses = user.get("assignedLicenses") or []
    for lic in licenses:
        if not isinstance(lic, dict):
            continue
        sku_id = lic.get("skuId")
        if sku_id and str(sku_id).lower() in MAIL_EXCHANGE_SKU_IDS:
            return True
    mail = user.get("mail")
    if mail and str(mail).strip():
        return True
    return False


def transform(input):
    # FEED CAVEAT: the integration's stated intent ("admins hold no mail/Exchange license")
    # needs role membership + assignedLicenses, but the current getUsers feed is a bare
    # GET /v1.0/users that carries neither. Until the feed is upgraded, this transform fails
    # with an explicit feed-update reason rather than pretending to evaluate (no name-pattern
    # heuristics). The rich branch below activates automatically once the feed carries
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
                fail_reasons=["Unexpected input format: expected a JSON object"]
            )

        if validation.get("status") == "failed":
            return create_response(
                result=default_result,
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        if "error" in data:
            error_info = data.get("error", {})
            inner_error = error_info.get("innerError", {})
            return create_response(
                result=default_result,
                validation={"status": "error", "errors": [error_info.get("message", "API error")], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get("code"), "innerErrorCode": inner_error.get("code") if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        users = data.get("value") or []
        if not isinstance(users, list):
            users = [users] if users else []

        user_count = len(users)
        users_by_id = {user.get("id"): user for user in users if isinstance(user, dict) and user.get("id")}

        has_license_data = any(isinstance(user, dict) and "assignedLicenses" in user for user in users)
        admin_principal_ids = _collect_admin_principal_ids(data, users)
        has_role_data = (
            bool(_as_list(data.get("directoryRoles")))
            or bool(_as_list(data.get("roleAssignments")))
            or len(admin_principal_ids) > 0
        )

        admin_count = 0
        admins_with_mail_license = 0
        admins_missing_from_user_feed = 0
        is_separate = False

        if has_license_data and has_role_data:
            for principal_id in admin_principal_ids:
                admin_count += 1
                user = users_by_id.get(principal_id)
                if user is None:
                    admins_missing_from_user_feed += 1
                    continue
                if _user_has_mail_or_exchange_license(user):
                    admins_with_mail_license += 1

            is_separate = (
                admin_count > 0
                and admins_with_mail_license == 0
                and admins_missing_from_user_feed == 0
            )

            if is_separate:
                pass_reasons.append(
                    f"All {admin_count} privileged admin account(s) are free of mail/Exchange Online licenses"
                )
            elif admin_count == 0:
                fail_reasons.append("No privileged directory role members found in user feed")
                recommendations.append("Verify directory role membership is included in the integration feed")
            elif admins_missing_from_user_feed > 0:
                fail_reasons.append(
                    f"{admins_missing_from_user_feed} privileged admin account(s) are not present in the user feed"
                )
                recommendations.append(
                    "Include privileged role members in the getUsers feed with assignedLicenses for license evaluation"
                )
            else:
                fail_reasons.append(
                    f"{admins_with_mail_license} of {admin_count} admin account(s) have mail/Exchange Online licenses"
                )
                recommendations.append("Use dedicated admin accounts without mail or Exchange Online licenses")
        else:
            fail_reasons.append(feed_update_reason)
            recommendations.append(feed_update_recommendation)

        return create_response(
            result={
                criteriaKey: is_separate,
                "userCount": user_count,
                "adminCount": admin_count,
                "adminsWithMailLicense": admins_with_mail_license,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"userCount": user_count, "hasLicenseData": has_license_data, "hasRoleData": has_role_data}
        )

    except Exception as e:
        return create_response(
            result=default_result,
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
