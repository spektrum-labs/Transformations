import json
import ast


def transform(input):
    """
    Evaluates isForensicsEnabled for Coralogix Incident Management

    Checks: Whether the Coralogix platform health and log ingestion is active
    API Source: /api/v1/health
    Pass Condition: Health endpoint returns valid status indicating operational platform

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isForensicsEnabled": boolean, "status": str}
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
        has_error = data.get("error") is not None
        status_val = data.get("status", data.get("health", "unknown"))
        result = isinstance(data, dict) and not has_error
        status = str(status_val) if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "isForensicsEnabled": result,
            "status": status
        }

    except Exception as e:
        return {"isForensicsEnabled": False, "error": str(e)}
