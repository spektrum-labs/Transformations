import json
import ast


def transform(input):
    """
    Evaluates isTicketingEnabled for Confluence Cloud

    Checks: Whether pages are retrievable from Confluence Cloud
    API Source: {baseURL}/wiki/api/v2/pages
    Pass Condition: The API returns a results array (even if empty)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isTicketingEnabled": boolean, "pageCount": int}
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
        results = data.get("results", data.get("data", []))

        if isinstance(results, list):
            result = True
            page_count = len(results)
        else:
            result = bool(data)
            page_count = 0
        # -- END EVALUATION LOGIC --

        return {
            "isTicketingEnabled": result,
            "pageCount": page_count
        }

    except Exception as e:
        return {"isTicketingEnabled": False, "error": str(e)}
