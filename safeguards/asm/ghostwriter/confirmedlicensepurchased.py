import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for Ghostwriter (ASM)

    Checks: Whether the Ghostwriter API token returns a valid authenticated user
    API Source: {baseURL}/v1/graphql (whoami query)
    Pass Condition: Response contains a valid username indicating active access

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean, "username": str, "role": str}
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

        # ── EVALUATION LOGIC ──
        gql_data = data.get("data", data)
        whoami = gql_data.get("whoami", gql_data)

        username = whoami.get("username", "")
        role = whoami.get("role", "")

        valid = bool(username)
        # ── END EVALUATION LOGIC ──

        return {
            "confirmedLicensePurchased": valid,
            "username": username,
            "role": role
        }

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
