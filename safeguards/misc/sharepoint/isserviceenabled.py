import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for SharePoint

    Checks: Whether site data is retrievable from SharePoint via Microsoft Graph
    API Source: https://graph.microsoft.com/v1.0/sites/{siteHostname}:/
    Pass Condition: The API returns a valid site object

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isServiceEnabled": boolean, "siteFound": boolean}
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
        site_id = data.get("id", "")
        result = bool(site_id) or (bool(data) and "error" not in data)
        # -- END EVALUATION LOGIC --

        return {
            "isServiceEnabled": result,
            "siteFound": bool(site_id)
        }

    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
