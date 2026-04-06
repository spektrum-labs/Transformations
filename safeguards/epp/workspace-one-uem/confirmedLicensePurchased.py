import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Workspace ONE UEM (EPP)

    Checks: Whether the Workspace ONE UEM environment is active and responding
    API Source: GET /api/system/info
    Pass Condition: API returns valid system information confirming active environment

    Parameters:
        input (dict): JSON data containing API response

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
        # Workspace ONE /api/system/info returns environment details
        result = False

        product_version = data.get("ProductVersion", data.get("productVersion", ""))
        environment = data.get("Environment", data.get("environment", ""))

        if product_version and isinstance(product_version, str) and len(product_version) > 0:
            result = True
        elif environment and isinstance(environment, str) and len(environment) > 0:
            result = True
        elif data and not data.get("error") and not data.get("errorCode"):
            result = True
        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": result,
            "productVersion": product_version
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
