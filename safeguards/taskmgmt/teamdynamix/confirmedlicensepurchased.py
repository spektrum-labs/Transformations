import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for TeamDynamix

    Checks: Whether the TeamDynamix instance has active licensed users
    API Source: https://{instance}.teamdynamix.com/TDWebApi/api/people/lookup
    Pass Condition: API returns a successful response with at least one person record

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "totalUsers": int}
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
        people = data if isinstance(data, list) else data.get("data", data.get("people", []))

        if not isinstance(people, list):
            people = [people] if isinstance(people, dict) else []

        total = len(people)
        result = total >= 1
        # -- END EVALUATION LOGIC --

        return {
            "confirmedLicensePurchased": result,
            "totalUsers": total
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
