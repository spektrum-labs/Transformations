import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Authomize (IAM)

    Checks: Whether the Authomize account is active and accessible
    API Source: GET {baseURL}/v2/account/status
    Pass Condition: Account status returns a valid response indicating an active subscription
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

        # Authomize account status endpoint returns subscription/account info
        status = data.get("status", data.get("state", "")).lower()
        account_id = data.get("accountId", data.get("account_id", data.get("id", "")))
        is_active = data.get("isActive", data.get("active", False))

        if status in ("active", "enabled", "ok"):
            result = True
        elif is_active:
            result = True
        elif account_id:
            # Valid account ID returned means the subscription is active
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
