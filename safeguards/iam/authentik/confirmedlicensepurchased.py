import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Authentik (IAM)

    Checks: Whether the Authentik instance is active and accessible
    API Source: GET {baseURL}/api/v3/admin/system/
    Pass Condition: System info returns a valid server version and runtime status
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

        # Authentik /api/v3/admin/system/ returns server_version, runtime info
        server_version = data.get("server_version", data.get("version", ""))
        runtime = data.get("runtime", {})
        http_host = data.get("http_host", "")

        if server_version or http_host:
            result = True
        elif isinstance(runtime, dict) and len(runtime) > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
