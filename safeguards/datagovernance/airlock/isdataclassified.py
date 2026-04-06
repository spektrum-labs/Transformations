import json
import ast


def transform(input):
    """
    Evaluates isDataClassified for Airlock WAF

    Checks: Whether at least one virtual host is configured for data protection
    API Source: https://{host}:4443/airlock/rest/configuration/virtual-hosts
    Pass Condition: At least one virtual host exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isDataClassified": boolean, "activeVirtualHosts": int, "totalVirtualHosts": int}
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
        hosts = data.get("data", data.get("virtualHosts", data.get("items", [])))

        if not isinstance(hosts, list):
            hosts = [hosts] if hosts else []

        total = len(hosts)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "isDataClassified": result,
            "activeVirtualHosts": total,
            "totalVirtualHosts": total
        }

    except Exception as e:
        return {"isDataClassified": False, "error": str(e)}
