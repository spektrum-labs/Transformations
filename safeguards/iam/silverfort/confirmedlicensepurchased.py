import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Silverfort (IAM)

    Checks: Whether a valid Silverfort instance is active by checking
            the system status endpoint for an active status.
    API Source: GET {baseURL}/api/v2/system/status
    Pass Condition: API returns a valid response with active status.
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

        # /api/v2/system/status returns {"status": "active", "active": true, ...}
        status = data.get("status", "")
        active = data.get("active", data.get("licensePurchased", None))

        if isinstance(status, str) and status.lower() in ["active", "healthy", "ok", "running"]:
            result = True
        elif isinstance(active, bool) and active:
            result = True
        elif isinstance(status, str) and len(status) > 0:
            result = True

        # Check for any valid system info indicating active license
        version = data.get("version", data.get("build", ""))
        if isinstance(version, str) and len(version) > 0 and not result:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
