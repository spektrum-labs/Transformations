import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Auth0 (IAM)

    Checks: Whether the Auth0 tenant is active and accessible
    API Source: GET {baseURL}/api/v2/tenants/settings
    Pass Condition: Tenant settings are returned with a valid friendly_name or tenant name
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

        # Auth0 tenant settings returns friendly_name, support_email, etc.
        friendly_name = data.get("friendly_name", "")
        tenant = data.get("tenant", data.get("name", ""))
        sandbox = data.get("sandbox_version", None)

        if friendly_name or tenant:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
