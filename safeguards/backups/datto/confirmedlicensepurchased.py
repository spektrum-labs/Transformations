# confirmedlicensepurchased.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Evaluates if the license has been purchased for Datto BCDR

    Parameters:
        input (dict): The JSON data containing Datto BCDR information.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
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

        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        
        default_value = True if data is not None else False

        license_purchased = data.get('licensePurchased', default_value)
        
        if not license_purchased:
            # Check if there are any devices (indicates active subscription)
            devices = (
                data.get("items", []) or
                data.get("devices", []) or
                data.get("agents", []) or
                data.get("data", {}).get("rows", [])
            )
            if len(devices) > 0:
                license_purchased = True
            
            # Check totalRecords
            if 'totalRecords' in data:
                if data['totalRecords'] > 0:
                    license_purchased = True

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}

