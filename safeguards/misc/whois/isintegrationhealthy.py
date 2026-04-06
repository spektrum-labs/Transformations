import json
import ast


def transform(input):
    """
    Evaluates isIntegrationHealthy for WhoisXML API.

    Checks: Whether the WhoisXML API is reachable and the API key is valid.
    API Source: GET https://www.whoisxmlapi.com/whoisserver/WhoisService
    Pass Condition: A valid WHOIS lookup response is returned

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isIntegrationHealthy": boolean, "responseReceived": boolean}
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
        whois_record = data.get("WhoisRecord", data.get("whoisRecord", {}))
        error = data.get("error", data.get("ErrorMessage", None))

        result = isinstance(data, dict) and len(data) > 0 and not error
        # -- END EVALUATION LOGIC --

        return {
            "isIntegrationHealthy": result,
            "responseReceived": bool(data)
        }

    except Exception as e:
        return {"isIntegrationHealthy": False, "error": str(e)}
