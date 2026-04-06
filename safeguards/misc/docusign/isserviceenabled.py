import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for DocuSign (Electronic Signatures)

    Checks: Whether the DocuSign envelopes endpoint is accessible
    API Source: GET {baseURL}/v2.1/accounts/{accountId}/envelopes
    Pass Condition: API returns a valid envelope listing response

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
        result = False

        envelopes = data.get("envelopes", None)
        result_set_size = data.get("resultSetSize", None)

        if envelopes is not None or result_set_size is not None:
            result = True
        elif isinstance(data, dict) and not data.get("errorCode"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}
    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
