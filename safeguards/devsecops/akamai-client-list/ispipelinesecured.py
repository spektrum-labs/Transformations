import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Akamai Client List

    Checks: Whether IP-based client lists are configured for pipeline protection
    API Source: {baseURL}/client-lists/v1/lists
    Pass Condition: At least one IP-type client list exists with active entries

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "activePolicies": int, "totalPolicies": int}
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
        lists = data.get("content", data.get("data", data.get("lists", data.get("items", []))))

        if not isinstance(lists, list):
            return {
                "isPipelineSecured": False,
                "activePolicies": 0,
                "totalPolicies": 0,
                "error": "Unexpected response format"
            }

        total = len(lists)
        active = []
        for item in lists:
            list_type = item.get("type", "")
            if list_type in ("IP", "GEO", "ASN", "TLS_FINGERPRINT"):
                items_count = item.get("itemsCount", item.get("itemCount", 0))
                if items_count and items_count > 0:
                    active.append(item)

        result = len(active) > 0
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "activePolicies": len(active),
            "totalPolicies": total
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
