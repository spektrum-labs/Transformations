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
            raise ValueError("Invalid input format")
    if isinstance(input, bytes):
        return json.loads(input.decode("utf-8"))
    if isinstance(input, dict):
        return input
    raise ValueError("Input must be JSON string, bytes, or dict")


def transform(input):
    """
    Checks if automated response capabilities are available

    Response capabilities:
    - Host isolation (Blumira Agent required)
    - Dynamic blocklists
    - M365 Threat Response (disable users)

    Available in: Response, Automate, XDR Platform editions

    Parameters:
        input (dict): Account/features response

    Returns:
        dict: {"isResponseCapabilityEnabled": boolean}
    """
    try:
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)

        features = data.get("features", {})
        license_edition = data.get("license", {}).get("edition", "").lower()

        # Editions with response capabilities
        response_editions = ["response", "automate", "xdr platform"]

        has_response = (
            features.get("automatedResponse", False) or
            any(ed in license_edition for ed in response_editions)
        )

        return {"isResponseCapabilityEnabled": has_response}

    except Exception as e:
        return {"isResponseCapabilityEnabled": False, "error": str(e)}
