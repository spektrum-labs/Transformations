import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Cobalt.io (Pentest as a Service)

    Checks: Whether the Cobalt organization account is active and accessible
    API Source: GET https://api.us.cobalt.io/orgs
    Pass Condition: API returns a valid organization object with an active resource

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

        # -- EVALUATION LOGIC --
        result = False

        # Check for valid organization data from Cobalt API
        org_data = data.get("data", [])
        if isinstance(org_data, list) and len(org_data) > 0:
            for org in org_data:
                resource = org.get("resource", {})
                if resource.get("id") or resource.get("name"):
                    result = True
                    break
        elif isinstance(org_data, dict):
            resource = org_data.get("resource", org_data)
            if resource.get("id") or resource.get("name"):
                result = True
        elif data.get("id") or data.get("name"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"confirmedLicensePurchased": result}
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
