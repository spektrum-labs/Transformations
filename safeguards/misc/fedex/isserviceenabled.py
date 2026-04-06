import json
import ast


def transform(input):
    """
    Evaluates isServiceEnabled for FedEx (Shipping / Logistics API)

    Checks: Whether the FedEx Track API is accessible
    API Source: POST https://apis.fedex.com/track/v1/trackingnumbers
    Pass Condition: API returns a valid tracking response

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

        track_results = data.get("completeTrackResults", data.get("output", None))
        transaction_id = data.get("transactionId", "")

        if track_results is not None:
            result = True
        elif transaction_id:
            result = True
        elif isinstance(data, dict) and not data.get("errors"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isServiceEnabled": result}
    except Exception as e:
        return {"isServiceEnabled": False, "error": str(e)}
