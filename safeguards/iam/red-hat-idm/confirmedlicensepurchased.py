import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Red Hat IDM (IAM)

    Checks: Whether a valid Red Hat IdM server is active by confirming
            the env command returns a version string.
    API Source: POST {baseURL}/ipa/session/json (method: env)
    Pass Condition: API returns a valid response with a non-empty version field.
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

        # IdM env command returns {"result": {"result": {"version": "4.x.x", ...}}}
        env_result = data.get("result", data)
        if isinstance(env_result, dict):
            env_result = env_result.get("result", env_result)

        version = ""
        if isinstance(env_result, dict):
            version = env_result.get("version", env_result.get("api_version", ""))

        if isinstance(version, str) and len(version) > 0:
            result = True
        elif isinstance(version, list) and len(version) > 0:
            result = True

        # Also check if status/licensePurchased was pre-extracted
        if not result:
            license_val = data.get("licensePurchased", data.get("status", ""))
            if isinstance(license_val, str) and len(license_val) > 0:
                result = True
            elif isinstance(license_val, bool):
                result = license_val
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result, "version": str(version)}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
