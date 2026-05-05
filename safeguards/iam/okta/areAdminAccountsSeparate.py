
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
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


# Admin naming heuristics: logins/emails that suggest a dedicated privileged account
ADMIN_PATTERNS = [
    "admin.",
    ".admin",
    "-admin",
    "admin-",
    "adm.",
    ".adm",
    "svc-",
    "priv.",
    ".priv",
    "privileged.",
    ".privileged",
    "sysadmin",
    "superadmin",
]


def has_admin_pattern(login):
    """Return True if the login string matches a known admin-account naming convention."""
    if not login:
        return False
    login_lower = login.lower()
    matched = False
    for pat in ADMIN_PATTERNS:
        if pat in login_lower:
            matched = True
            break
    if matched:
        return True
    # Also catch logins where the local part starts with "admin" followed by more characters
    # (e.g. "adminjohn@domain.com") but not the word "admin" alone (a generic account name)
    local_part = login_lower.split("@")[0] if "@" in login_lower else login_lower
    if local_part.startswith("admin") and len(local_part) > 5:
        return True
    return False


def transform(input):
    data, validation = extract_input(input)

    # listUsers returns a JSON array directly; handle both a raw list and dict wrappers
    users = []
    if isinstance(data, list):
        users = data
    elif isinstance(data, dict):
        for key in ["users", "data", "items", "value"]:
            candidate = data.get(key)
            if isinstance(candidate, list):
                users = candidate
                break

    total_users = len(users)
    admin_pattern_accounts = []
    standard_accounts = []

    for user in users:
        if not isinstance(user, dict):
            continue
        profile = user.get("profile") or {}
        if isinstance(profile, dict):
            login = profile.get("login") or profile.get("email") or ""
            email = profile.get("email") or ""
        else:
            login = ""
            email = ""
        user_id = user.get("id") or ""
        status = user.get("status") or ""

        if has_admin_pattern(login) or has_admin_pattern(email):
            admin_pattern_accounts.append({
                "id": user_id,
                "login": login,
                "status": status,
            })
        else:
            standard_accounts.append({
                "id": user_id,
                "login": login,
                "status": status,
            })

    total_admin_pattern = len(admin_pattern_accounts)
    total_standard = len(standard_accounts)

    has_admin_accounts = total_admin_pattern > 0
    has_standard_accounts = total_standard > 0
    are_separate = has_admin_accounts and has_standard_accounts

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if total_users == 0:
        fail_reasons.append(
            "No user accounts were returned by the API. Cannot confirm that admin "
            "accounts are separated from standard accounts without user data."
        )
        recommendations.append(
            "Ensure the API token has permission to list users and that the tenant "
            "contains active user accounts. Verify account separation manually."
        )
    elif are_separate:
        pass_reasons.append(
            f"Detected {total_admin_pattern} account(s) with admin-pattern login names "
            f"(e.g. 'admin.', '-admin', 'svc-', 'privileged.') alongside "
            f"{total_standard} standard account(s) out of {total_users} total users. "
            "This naming pattern indicates dedicated privileged accounts are used "
            "separately from day-to-day user accounts."
        )
        if total_admin_pattern <= 10:
            sample_logins = [a["login"] for a in admin_pattern_accounts[:5]]
            additional_findings.append(
                f"Sample admin-pattern accounts: {', '.join(sample_logins)}"
            )
    else:
        if not has_admin_accounts:
            fail_reasons.append(
                f"None of the {total_users} user account(s) returned match known "
                "admin-account naming conventions (e.g. 'admin.', '-admin', 'svc-', "
                "'privileged.'). This suggests admin users may not be using dedicated "
                "separate accounts for privileged actions."
            )
            recommendations.append(
                "Establish a naming convention for privileged accounts (e.g. "
                "'admin.firstname@domain.com') and provision dedicated accounts for "
                "all administrators. Exclude these accounts from email, web browsing, "
                "and standard productivity tooling."
            )
        elif not has_standard_accounts:
            fail_reasons.append(
                f"All {total_users} account(s) returned appear to match admin-pattern "
                "naming conventions with no standard user accounts detected. Cannot "
                "confirm separation without evidence of both account types."
            )
            recommendations.append(
                "Verify that the API response includes all user types. Confirm that "
                "standard (non-privileged) user accounts exist and are not named with "
                "admin patterns."
            )

    return create_response(
        result={
            "areAdminAccountsSeparate": are_separate,
            "totalUsersInSample": total_users,
            "adminPatternAccountCount": total_admin_pattern,
            "standardAccountCount": total_standard,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalUsersInSample": total_users,
            "adminPatternAccountCount": total_admin_pattern,
            "standardAccountCount": total_standard,
        },
        metadata={
            "transformationId": "areAdminAccountsSeparate",
            "vendor": "Okta",
            "category": "iam",
        },
    )
