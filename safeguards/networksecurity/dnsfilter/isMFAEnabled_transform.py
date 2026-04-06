"""
Transformation: isMFAEnabled
Vendor: DNSFilter
Category: Network Security

Verifies MFA is enabled for DNSFilter admin accounts.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnabled", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "isMFAEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        users = data if isinstance(data, list) else []
        if isinstance(data, dict):
            users = data.get("users", [])

        if not users:
            fail_reasons.append("No user data available")
            recommendations.append("Verify DNSFilter API integration returns user data")
            return create_response(
                result={criteriaKey: False, "usersWithMFA": 0, "totalAdmins": 0},
                validation=validation,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                input_summary={"totalUsers": 0}
            )

        admin_users = []
        mfa_enabled_count = 0

        for user in users:
            if not isinstance(user, dict):
                continue
            permissions = user.get("permissions", {})
            if not isinstance(permissions, dict):
                permissions = {}
            role = str(permissions.get("role", "")).lower()

            if role in ("admin", "owner", "super_admin", "administrator"):
                admin_users.append(user)
                if user.get("mfa_enabled", False):
                    mfa_enabled_count = mfa_enabled_count + 1

        # If no explicit admins found, check all users
        if not admin_users:
            admin_users = users
            mfa_enabled_count = 0
            for u in users:
                if isinstance(u, dict) and u.get("mfa_enabled", False):
                    mfa_enabled_count = mfa_enabled_count + 1

        total_admins = len(admin_users)
        all_mfa_enabled = mfa_enabled_count == total_admins and total_admins > 0

        if all_mfa_enabled:
            pass_reasons.append(f"MFA enabled for all {total_admins} admin user(s)")
        else:
            remaining = total_admins - mfa_enabled_count
            fail_reasons.append(f"MFA not enabled for {remaining} of {total_admins} admin user(s)")
            recommendations.append("Enable MFA for all DNSFilter admin accounts")

        return create_response(
            result={criteriaKey: all_mfa_enabled, "usersWithMFA": mfa_enabled_count, "totalAdmins": total_admins},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalAdmins": total_admins, "mfaEnabled": mfa_enabled_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
