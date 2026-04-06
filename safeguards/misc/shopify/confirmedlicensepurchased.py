import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Shopify

    Checks: Whether the Shopify access token has valid access to the shop endpoint
    API Source: https://{storeName}.myshopify.com/admin/api/{version}/shop.json
    Pass Condition: A valid shop object with plan information is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "plan": str, "status": str}
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

        # -- EVALUATION LOGIC --
        shop = data.get("shop", data)
        shop_id = shop.get("id", "") if isinstance(shop, dict) else ""
        plan_name = shop.get("plan_name", "unknown") if isinstance(shop, dict) else "unknown"
        result = bool(shop_id) or (bool(data) and "error" not in data)
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "plan": plan_name,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
