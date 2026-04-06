import json
import ast


def transform(input):
    """
    Evaluates isLifeCycleManagementEnabled for Authentik (IAM)

    Checks: Whether proper user provisioning and deprovisioning with active/inactive status handling exists
    API Source: GET {baseURL}/api/v3/core/users/
    Pass Condition: Evidence of lifecycle management via inactive users or user type differentiation
    """
    try:
        def _parse_input(raw):
            if isinstance(raw, str):
                try:
                    parsed = ast.literal_eval(raw)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                try:
                    raw = raw.replace("'", '"')
                    return json.loads(raw)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        users = data.get("results", data.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            has_inactive = False
            has_type_differentiation = False
            user_types = set()

            for user in users:
                # Authentik tracks is_active for lifecycle management
                if user.get("is_active", True) is False:
                    has_inactive = True
                # Check for user type differentiation (internal, external, service_account)
                user_type = user.get("type", "")
                if user_type:
                    user_types.add(user_type)

            has_type_differentiation = len(user_types) >= 2

            # Lifecycle management exists if there are inactive users or type differentiation
            result = has_inactive or has_type_differentiation
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
