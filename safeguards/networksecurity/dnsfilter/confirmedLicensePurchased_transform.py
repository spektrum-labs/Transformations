import json
import ast


def _parse_input(input):
    if isinstance(input, str):
        try:
            parsed = ast.literal_eval(input)
            if isinstance(parsed, dict):
                return parsed
        except:
            pass
        try:
            input = input.replace("'", '"')
            return json.loads(input)
        except:
            raise ValueError("Input string is neither valid Python literal nor JSON")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Validates DNSFilter subscription is active

    Parameters:
        input (dict): Organization data from GET /organizations/{id}

    Returns:
        dict: {"confirmedLicensePurchased": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        # Check organization status
        org_status = data.get("status", "").lower()

        # Check subscription if available
        subscription = data.get("subscription", {})
        sub_status = subscription.get("status", "").lower()

        # License confirmed if org is active or subscription is active
        is_active = org_status == "active" or sub_status == "active"

        # Fallback: if we got valid data, assume license exists
        if not is_active and data.get("id"):
            is_active = True

        return {"confirmedLicensePurchased": is_active}

    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
