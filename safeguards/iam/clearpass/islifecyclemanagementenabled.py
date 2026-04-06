import json
import ast


def transform(input):
    """
    Evaluates isLifeCycleManagementEnabled for ClearPass (IAM)

    Checks: Whether proper user provisioning and expiration policies exist for guest and local accounts
    API Source: GET {baseURL}/api/local-user
    Pass Condition: Evidence of lifecycle management via account expiration dates or disabled accounts
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

        items = data.get("_embedded", {}).get("items", data.get("items", data.get("data", [])))

        if isinstance(items, list) and len(items) > 0:
            has_disabled = False
            has_expiration = False

            for user in items:
                # Check for disabled accounts
                enabled = user.get("enabled", True)
                if enabled is False or str(enabled).lower() == "false":
                    has_disabled = True
                # Check for expiration date management
                expiry = user.get("expire_time", user.get("expiration", user.get("account_expires", None)))
                if expiry is not None and str(expiry) not in ("", "0", "never", "None"):
                    has_expiration = True

            # Lifecycle management exists if there are disabled accounts or expiration policies
            result = has_disabled or has_expiration
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
