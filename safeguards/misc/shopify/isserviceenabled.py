import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for Shopify

    Checks: Whether products are retrievable from the Shopify store
    API Source: https://{storeName}.myshopify.com/admin/api/{version}/products.json
    Pass Condition: The API returns a products array

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean, "productCount": int}
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
        products = data.get("products", [])
        if isinstance(products, list):
            result = True
            product_count = len(products)
        else:
            result = bool(data) and "error" not in data
            product_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "productCount": product_count
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
