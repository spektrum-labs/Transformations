import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for ScienceLogic SL1

    Checks: Whether the ScienceLogic API returns a valid license response
    API Source: GET {baseURL}/api/license
    Pass Condition: A successful API response indicating active license access

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
        status = data.get("status", "")
        if isinstance(status, str):
            status = status.lower()

        valid_statuses = {"active", "trial", "ok", "success", "valid"}
        result = status in valid_statuses

        if not result:
            result_set = data.get("result_set", data.get("data", []))
            if isinstance(result_set, (list, dict)) and len(result_set) > 0:
                result = True
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
