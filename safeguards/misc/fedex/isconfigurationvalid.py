import json
import ast


def transform(input):
    """
    Evaluates isConfigurationValid for FedEx (Shipping / Logistics API)

    Checks: Whether the FedEx reference data is accessible
    API Source: GET https://apis.fedex.com/country/v1/countries
    Pass Condition: API returns valid reference data confirming proper configuration

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isConfigurationValid": boolean}
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
        result = False

        countries = data.get("countries", data.get("output", None))

        if isinstance(countries, list) and len(countries) > 0:
            result = True
        elif isinstance(data, dict) and not data.get("errors"):
            result = True
        # -- END EVALUATION LOGIC --

        return {"isConfigurationValid": result}
    except Exception as e:
        return {"isConfigurationValid": False, "error": str(e)}
