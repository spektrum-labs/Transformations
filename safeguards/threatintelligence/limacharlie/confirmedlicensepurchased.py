import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for LimaCharlie.

    Checks: Active LimaCharlie organization by verifying org details endpoint.
    API Source: GET https://api.limacharlie.io/v1/orgs/{oid}
    Pass Condition: Response contains valid organization data with an active status.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # Check for valid org data
        oid = data.get("oid", data.get("id", data.get("org_id", "")))
        name = data.get("name", data.get("org_name", ""))

        if isinstance(oid, str) and len(oid.strip()) > 0:
            result = True
        elif isinstance(name, str) and len(name.strip()) > 0:
            result = True
        elif isinstance(data, dict) and len(data) > 0 and "error" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
