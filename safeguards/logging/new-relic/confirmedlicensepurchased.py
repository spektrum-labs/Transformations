import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for New Relic

    Checks: Whether the New Relic account is active with at least one application reporting
    API Source: https://api.newrelic.com/v2/applications.json
    Pass Condition: API returns a valid response with application data

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "accountActive": boolean}
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
        error = data.get("error", None)
        applications = data.get("applications", None)

        result = error is None and applications is not None
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "accountActive": result
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
