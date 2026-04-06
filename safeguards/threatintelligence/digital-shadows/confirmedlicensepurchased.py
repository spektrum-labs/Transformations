import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Digital Shadows (ReliaQuest).

    Checks: Active Digital Shadows subscription via subscription status endpoint
    API Source: GET https://api.searchlight.app/v1/subscription/status
    Pass Condition: Response contains valid subscription data without errors

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
        has_error = data.get("errors") is not None or data.get("error") is not None
        sub_status = data.get("status", data.get("subscription_status", ""))
        if isinstance(sub_status, str):
            sub_status = sub_status.lower()

        active_statuses = {"active", "valid", "trial", "enterprise"}
        result = sub_status in active_statuses or (isinstance(data, dict) and not has_error and len(data) > 0)
        status = "active" if result else "inactive"
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "status": status
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
