import json
import ast


def transform(input):
    """Evaluates confirmedLicensePurchased for CyberArk Privilege Cloud (IAM)

    Checks whether the CyberArk Privilege Cloud tenant is active by verifying
    the system health endpoint returns a valid active component status.

    Parameters:
        input (dict): JSON data containing API response from getLicenseStatus

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # CyberArk system health returns component status
        is_active = data.get("IsActive", data.get("isActive", False))
        status = data.get("status", data.get("Status", ""))

        if is_active is True or str(is_active).lower() == "true":
            result = True
        elif isinstance(status, str) and status.lower() in ("active", "ok", "running"):
            result = True
        elif data.get("licensePurchased", False):
            result = True
        # ── END EVALUATION LOGIC ──

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
