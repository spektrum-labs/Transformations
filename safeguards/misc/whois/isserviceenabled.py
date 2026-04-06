import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for WhoisXML API.

    Checks: Whether the WHOIS lookup service is active by confirming a test
            domain lookup returns valid WHOIS data.
    API Source: GET https://www.whoisxmlapi.com/whoisserver/WhoisService
    Pass Condition: API returns a WhoisRecord with domain information

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean}
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
        if not isinstance(whois_record, dict):
            whois_record = {}

        domain_name = whois_record.get("domainName", data.get("domainName", ""))
        error = data.get("error", data.get("ErrorMessage", None))

        if error:
            result = False
        elif domain_name:
            result = True
        elif isinstance(whois_record, dict) and len(whois_record) > 0:
            result = True
        else:
            result = False
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
