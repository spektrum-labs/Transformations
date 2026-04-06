import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Google Cloud Pub/Sub

    Checks: Whether the Google Cloud project has Pub/Sub API enabled
    API Source: https://pubsub.googleapis.com/v1/projects/{projectId}/topics
    Pass Condition: API returns a valid response with topics list (even if empty)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "projectActive": boolean}
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
        topics = data.get("topics", None)
        error = data.get("error", None)

        result = error is None and topics is not None
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "projectActive": result
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
