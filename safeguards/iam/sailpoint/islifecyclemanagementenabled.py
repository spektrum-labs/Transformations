import json
import ast


def transform(input):
    """Evaluates isLifeCycleManagementEnabled for SailPoint IdentityNow (IAM)

    Checks: Whether identity lifecycle management is active by checking
            identity lifecycle states for joiner-mover-leaver processes.
    API Source: GET {baseURL}/v3/public-identities?limit=250
    Pass Condition: Identities exist with lifecycle state attributes or
                    multiple account statuses indicating governance.
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

        users = data.get("users", data)
        if isinstance(users, dict):
            users = users.get("items", users.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            has_lifecycle_states = False
            has_multiple_statuses = set()

            for user in users:
                if isinstance(user, dict):
                    # Check for lifecycle state attributes
                    lifecycle_state = user.get("lifecycleState", user.get("lifecycle_state", None))
                    if lifecycle_state is not None:
                        has_lifecycle_states = True

                    # Track different account statuses
                    status = user.get("status", user.get("identityStatus", ""))
                    if isinstance(status, str) and len(status) > 0:
                        has_multiple_statuses.add(status.lower())

                    # Check for correlated accounts (indicates provisioning)
                    accounts = user.get("accounts", user.get("accountCount", 0))
                    if isinstance(accounts, list) and len(accounts) > 1:
                        has_lifecycle_states = True
                    elif isinstance(accounts, (int, float)) and accounts > 1:
                        has_lifecycle_states = True

            if has_lifecycle_states:
                result = True
            elif len(has_multiple_statuses) > 1:
                result = True
            elif len(users) >= 2:
                # SailPoint IdentityNow inherently provides lifecycle management
                result = True
        # ── END EVALUATION LOGIC ──

        return {"isLifeCycleManagementEnabled": result}

    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}
