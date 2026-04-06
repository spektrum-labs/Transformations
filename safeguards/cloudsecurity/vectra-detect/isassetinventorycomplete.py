import json
import ast


def transform(input):
    """
    Evaluates isAssetInventoryComplete for Vectra Detect

    Checks: Whether Vectra Detect has monitored hosts in its inventory
    API Source: {baseURL}/api/v2.5/hosts
    Pass Condition: At least one host is being monitored by the Vectra brain

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isAssetInventoryComplete": boolean, "totalDevices": int}
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
        hosts = data.get("results", data.get("data", data.get("hosts", data.get("items", []))))
        count = data.get("count", data.get("total", 0))

        if isinstance(hosts, list):
            total = max(len(hosts), count)
        elif isinstance(count, int):
            total = count
        else:
            total = 0

        result = total > 0
        # -- END EVALUATION LOGIC --

        return {
            "isAssetInventoryComplete": result,
            "totalDevices": total
        }

    except Exception as e:
        return {"isAssetInventoryComplete": False, "error": str(e)}
