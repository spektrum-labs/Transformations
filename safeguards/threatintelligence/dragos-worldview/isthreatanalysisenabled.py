import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for Dragos WorldView.

    Checks: Whether intelligence products (reports) are available
    API Source: GET https://portal.dragos.com/api/v1/products
    Pass Condition: At least one intelligence product/report exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean, "reportCount": int}
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
        products = data.get("products", data.get("data", data.get("results", [])))
        if not isinstance(products, list):
            products = []

        count = len(products)
        result = count >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isThreatAnalysisEnabled": result,
            "reportCount": count
        }

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
