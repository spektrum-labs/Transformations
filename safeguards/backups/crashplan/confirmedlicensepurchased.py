# confirmedlicensepurchased.py - CrashPlan

import json
import ast

def transform(input):
    """
    Validates that CrashPlan API is accessible and returns license status
    based on successful authentication and user retrieval.

    Parameters:
        input (dict): The JSON data from CrashPlan getCurrentUser endpoint.

    Returns:
        dict: A dictionary indicating if license is confirmed.
    """
    try:
        def _parse_input(input):
            if isinstance(input, str):
                try:
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")

        # Parse input
        data = _parse_input(input)

        # Drill down past response/result wrappers if present
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # License is confirmed if we can successfully retrieve user info
        # Check for user identifiers that indicate successful API access
        user_id = data.get("userId", data.get("userUid", ""))
        username = data.get("username", "")
        email = data.get("email", "")
        status = data.get("status", "")
        org_id = data.get("orgId", data.get("orgUid", ""))

        # License is valid if we have user data and user is active
        is_licensed = bool(user_id or username or email)
        is_active = status.lower() == "active" if status else True

        confirmed = is_licensed and is_active

        return {
            "confirmedLicensePurchased": confirmed,
            "userId": str(user_id),
            "username": username,
            "email": email,
            "status": status,
            "orgId": str(org_id)
        }

    except json.JSONDecodeError:
        return {"confirmedLicensePurchased": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
