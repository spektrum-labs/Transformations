"""
Transformation: areAdminAccountsSeparate
Criterion: PM-ID-05.5 - Admin accounts must be separate from standard user accounts.
Method: listUsers
Heuristic: inspects profile.login values for dedicated admin-account naming patterns.
Note: Full verification requires cross-referencing with role assignments (listUserRoles),
which is not in the current method catalogue. This transform performs best-effort
heuristic detection based on login naming conventions.
"""

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


# Common naming patterns that indicate a dedicated privileged/admin account
ADMIN_PATTERNS = [
    "admin", "adm-", "-adm", "_adm", "adm_", "svcadm", "svc-adm",
    "padmin", "priv", "-admin", "admin-", "admin.", ".admin",
]


def has_admin_pattern(login):
    """Return True if the login string matches a known admin-account naming pattern."""
    if not login:
        return False
    login_lower = login.lower()
    for pattern in ADMIN_PATTERNS:
        if pattern in login_lower:
            return True
    return False


def transform(input_data):
    data, validation = extract_input(input_data)
    data = data if isinstance(data, dict) else {}

    # The Okta listUsers API returns an array; after extract_input the
    # outer dict retains the apiResponse key (list values are NOT unwrapped).
    users_raw = data.get("apiResponse") or []
    if not isinstance(users_raw, list):
        users_raw = []

    total_users = len(users_raw)
    active_users = [u for u in users_raw if isinstance(u, dict) and u.get("status") == "ACTIVE"]
    total_active = len(active_users)

    # Count how many active users expose a login field and detect admin patterns
    logins_visible = 0
    admin_pattern_accounts = []
    for u in active_users:
        profile = u.get("profile") or {}
        login = profile.get("login") or ""
        if login:
            logins_visible = logins_visible + 1
        if has_admin_pattern(login):
            admin_pattern_accounts.append({
                "id": u.get("id", ""),
                "login": login,
            })

    admin_pattern_count = len(admin_pattern_accounts)

    if total_active == 0:
        return create_response(
            result={
                "areAdminAccountsSeparate": False,
                "totalUsers": total_users,
                "activeUsers": 0,
                "adminPatternAccounts": 0,
            },
            validation=validation,
            fail_reasons=[
                "No active users found in the response; cannot assess account separation."
            ],
            recommendations=[
                "Ensure the API token has sufficient permissions to enumerate users "
                "and that users exist in the tenant."
            ],
            input_summary={
                "totalUsers": total_users,
                "activeUsers": 0,
                "loginsVisible": 0,
            },
            metadata={
                "transformationId": "areAdminAccountsSeparate",
                "vendor": "Okta",
                "category": "iam",
            },
        )

    if logins_visible == 0:
        return create_response(
            result={
                "areAdminAccountsSeparate": False,
                "totalUsers": total_users,
                "activeUsers": total_active,
                "adminPatternAccounts": 0,
            },
            validation=validation,
            fail_reasons=[
                f"Found {total_active} active users but no profile.login values were available "
                "for inspection. Cannot determine whether dedicated admin accounts exist "
                "separately from standard accounts."
            ],
            recommendations=[
                "Verify that the API token has the User Administrator or Super Administrator "
                "scope to read user profiles. Ensure administrators use dedicated accounts "
                "with identifiable naming conventions (e.g., 'admin.firstname@domain.com') "
                "to allow heuristic detection."
            ],
            input_summary={
                "totalUsers": total_users,
                "activeUsers": total_active,
                "loginsVisible": 0,
            },
            metadata={
                "transformationId": "areAdminAccountsSeparate",
                "vendor": "Okta",
                "category": "iam",
            },
        )

    if admin_pattern_count > 0:
        sample_logins = [a["login"] for a in admin_pattern_accounts[:3]]
        sample_str = ", ".join(sample_logins) if sample_logins else ""
        pass_reasons = [
            f"Detected {admin_pattern_count} active account(s) with admin-specific naming "
            f"patterns among {total_active} active users ({logins_visible} profile.login values "
            f"inspected). Sample admin-pattern logins: {sample_str}. "
            "This indicates dedicated privileged accounts exist separately from standard "
            "user accounts, consistent with account separation policy."
        ]
        return create_response(
            result={
                "areAdminAccountsSeparate": True,
                "totalUsers": total_users,
                "activeUsers": total_active,
                "adminPatternAccounts": admin_pattern_count,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary={
                "totalUsers": total_users,
                "activeUsers": total_active,
                "loginsVisible": logins_visible,
                "adminPatternAccounts": admin_pattern_count,
            },
            additional_findings=[
                "This assessment is heuristic-based on profile.login naming patterns. "
                "Full verification of role-based admin account separation requires "
                "cross-referencing with Okta role assignments via the Admin Roles API."
            ],
            metadata={
                "transformationId": "areAdminAccountsSeparate",
                "vendor": "Okta",
                "category": "iam",
            },
        )

    # No admin-pattern accounts detected
    return create_response(
        result={
            "areAdminAccountsSeparate": False,
            "totalUsers": total_users,
            "activeUsers": total_active,
            "adminPatternAccounts": 0,
        },
        validation=validation,
        fail_reasons=[
            f"No active accounts with admin-specific naming patterns were detected "
            f"among {total_active} active users ({logins_visible} profile.login values "
            "inspected). No evidence found of dedicated privileged accounts separate from "
            "standard user accounts."
        ],
        recommendations=[
            "Create dedicated administrator accounts distinct from daily-use accounts "
            "(e.g., 'admin.firstname@domain.com' or 'adm-username@domain.com'). "
            "Ensure privileged accounts are used exclusively for administrative tasks "
            "and are excluded from email, web browsing, and standard productivity tooling."
        ],
        input_summary={
            "totalUsers": total_users,
            "activeUsers": total_active,
            "loginsVisible": logins_visible,
            "adminPatternAccounts": 0,
        },
        metadata={
            "transformationId": "areAdminAccountsSeparate",
            "vendor": "Okta",
            "category": "iam",
        },
    )
