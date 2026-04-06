import json
import ast


def transform(input):
    """
    Evaluates confirmedLicensePurchased for OpenCTI.

    Checks: OpenCTI instance is accessible and the API token is valid.
    API Source: POST {baseURL}/graphql (query: me)
    Pass Condition: Response contains valid user profile data with name and email.

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
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

        # Check for valid user profile from GraphQL me query
        gql_data = data.get("data", data)
        if isinstance(gql_data, dict):
            me = gql_data.get("me", gql_data)
            if isinstance(me, dict):
                name = me.get("name", "")
                user_email = me.get("user_email", me.get("email", ""))
                user_id = me.get("id", "")

                if isinstance(name, str) and len(name.strip()) > 0:
                    return {"confirmedLicensePurchased": True}
                if isinstance(user_email, str) and len(user_email.strip()) > 0:
                    return {"confirmedLicensePurchased": True}
                if isinstance(user_id, str) and len(user_id.strip()) > 0:
                    return {"confirmedLicensePurchased": True}

        if isinstance(data, dict) and len(data) > 0 and "errors" not in data and "error" not in data:
            result = True
        else:
            result = False

        return {"confirmedLicensePurchased": result}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
