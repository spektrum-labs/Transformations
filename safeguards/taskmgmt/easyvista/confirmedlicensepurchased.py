import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for EasyVista (ITSM)

    Checks: Whether the EasyVista instance returns a valid API response
    API Source: {baseURL}/api/v1/{accountId}/requests?max_rows=1
    Pass Condition: API returns a successful response with no error

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
        records = data.get("records", data.get("RECORDS", data.get("results", [])))

        if error:
            result = False
            status = "error"
        elif isinstance(records, list):
            result = True
            status = "active"
        else:
            result = not bool(error)
            status = "active" if result else "unknown"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
