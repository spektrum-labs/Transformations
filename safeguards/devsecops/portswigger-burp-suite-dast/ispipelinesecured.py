import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Burp Suite DAST (Dynamic Application Security Testing)

    Checks: Whether scan configurations are defined to enforce security policies
    API Source: GET {baseURL}/api/scan_configs
    Pass Condition: At least one scan configuration exists

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean}
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

        # Check for scan configurations enforcing security policies
        configs = data.get("scan_configs", data.get("data", data.get("configurations", [])))
        if isinstance(configs, list) and len(configs) > 0:
            for config in configs:
                if isinstance(config, dict):
                    name = config.get("name", config.get("id", ""))
                    if name:
                        result = True
                        break
        elif data.get("total_count", 0) > 0:
            result = True
        # -- END EVALUATION LOGIC --

        return {"isPipelineSecured": result}
    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
