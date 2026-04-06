import json
import ast


def transform(input):
    """
    Evaluates isThreatAnalysisEnabled for IPWHOIS.

    Checks: IP lookup reports are accessible and returning enriched data.
    API Source: GET https://ipwhois.app/json/8.8.8.8
    Pass Condition: Response contains enriched IP data including ASN and org info.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isThreatAnalysisEnabled": boolean}
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

        # Check for enriched IP data
        ip = data.get("ip", "")
        org = data.get("org", data.get("connection", {}).get("org", ""))
        asn = data.get("asn", data.get("connection", {}).get("asn", ""))

        if isinstance(ip, str) and len(ip.strip()) > 0:
            result = True
        elif isinstance(org, str) and len(org.strip()) > 0:
            result = True
        elif isinstance(asn, str) and len(asn.strip()) > 0:
            result = True
        else:
            result = False

        return {"isThreatAnalysisEnabled": result}

    except Exception as e:
        return {"isThreatAnalysisEnabled": False, "error": str(e)}
