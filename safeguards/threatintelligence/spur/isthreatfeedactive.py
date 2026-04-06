import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for Spur.

    Checks: Whether the IP context endpoint returns VPN/proxy/bot classification data
    API Source: GET https://api.spur.us/v2/context/{ip}
    Pass Condition: Response contains valid IP enrichment with threat classification

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatFeedActive": boolean, "indicatorCount": int}
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
        has_error = data.get("error") is not None
        ip = data.get("ip", data.get("as", None))
        tunnels = data.get("tunnels", [])
        risks = data.get("risks", [])

        count = len(tunnels) + len(risks) if isinstance(tunnels, list) and isinstance(risks, list) else 0
        result = not has_error and ip is not None and isinstance(data, dict) and len(data) > 1
        # -- END EVALUATION LOGIC --

        return {
            "isThreatFeedActive": result,
            "indicatorCount": count
        }

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
