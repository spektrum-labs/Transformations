import json
import ast


def transform(input):
    """
    Evaluates isSecretManagementEnabled for Nozomi Networks

    Checks: Whether network node monitoring and asset inventory is active
    API Source: {baseURL}/api/open/query/do?query=nodes | count
    Pass Condition: Node count is greater than zero indicating active asset monitoring

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isSecretManagementEnabled": boolean, "nodeCount": int, "monitoringActive": boolean}
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
        count = data.get("count", data.get("total", 0))

        if isinstance(count, str):
            try:
                count = int(count)
            except ValueError:
                count = 0

        monitoring_active = count > 0

        result = monitoring_active
        # -- END EVALUATION LOGIC --

        return {
            "isSecretManagementEnabled": result,
            "nodeCount": count,
            "monitoringActive": monitoring_active
        }

    except Exception as e:
        return {"isSecretManagementEnabled": False, "error": str(e)}
