import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for Zero Networks (Network Security)"""
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
                    raise ValueError("Invalid input")
            if isinstance(raw, bytes):
                return json.loads(raw.decode("utf-8"))
            if isinstance(raw, dict):
                return raw
            raise ValueError("Input must be JSON string, bytes, or dict")

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # -- EVALUATION LOGIC --
        result = False

        # Zero Networks /api/v1/settings/license returns license/subscription info
        license_data = data.get("license", data)
        if isinstance(license_data, dict):
            status = license_data.get("status", license_data.get("state", ""))
            if isinstance(status, str) and status.lower() in ("active", "valid", "enabled"):
                result = True
            elif license_data.get("expiresAt", "") or license_data.get("expires_at", ""):
                result = True
            elif license_data.get("id", "") or license_data.get("type", ""):
                result = True

        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
