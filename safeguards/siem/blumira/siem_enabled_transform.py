import json
import ast


def _parse_input(input):
    if isinstance(input, str):
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Invalid input format")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Verifies SIEM is active by checking for findings API access

    SIEM is enabled if:
    - API returns valid response (not error)
    - Findings structure exists

    Parameters:
        input (dict): Findings API response

    Returns:
        dict: {"isSIEMEnabled": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # SIEM is enabled if we can access findings endpoint
        # Empty findings array still indicates active SIEM
        findings = data.get("findings", None)

        is_enabled = findings is not None

        return {"isSIEMEnabled": is_enabled}

    except Exception as e:
        return {"isSIEMEnabled": False, "error": str(e)}
