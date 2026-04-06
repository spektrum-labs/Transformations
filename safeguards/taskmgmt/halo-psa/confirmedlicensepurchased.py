import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Halo PSA (Professional Services Automation)

    Checks: Whether the Halo PSA instance returns a valid API response
    API Source: {baseURL}/api/tickets?count=1
    Pass Condition: API returns a successful response confirming active subscription

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "status": str}
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
        tickets = data.get("tickets", data.get("records", data.get("results", [])))
        record_count = data.get("record_count", len(tickets) if isinstance(tickets, list) else 0)

        if error:
            result = False
            status = "error"
        else:
            result = True
            status = "active"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
