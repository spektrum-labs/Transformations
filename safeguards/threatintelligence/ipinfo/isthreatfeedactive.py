import json
import ast


def transform(input):
    """
    Evaluates isThreatFeedActive for IPinfo.

    Checks: IP geolocation data feed is accessible and returning valid data.
    API Source: GET https://ipinfo.io/lite/8.8.8.8
    Pass Condition: Response contains valid IP geolocation fields (ip, country, etc.).

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatFeedActive": boolean}
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

        # Check for valid IP data
        ip = data.get("ip", "")
        country = data.get("country", data.get("country_code", ""))

        if isinstance(ip, str) and len(ip.strip()) > 0:
            result = True
        elif isinstance(country, str) and len(country.strip()) > 0:
            result = True
        else:
            result = False

        return {"isThreatFeedActive": result}

    except Exception as e:
        return {"isThreatFeedActive": False, "error": str(e)}
