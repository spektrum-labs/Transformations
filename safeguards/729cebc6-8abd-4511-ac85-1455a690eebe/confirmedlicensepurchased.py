import json
import ast

def transform(input):
    """
    Evaluates if the license has been purchased for the given Backup Provider

    Parameters:
        input (dict): The JSON data containing Backup Provider information.

    Returns:
        dict: A dictionary summarizing the license purchase information.
    """

    try:
        def _parse_input(input):
            if isinstance(input, str):
                # First try to parse as literal Python string representation
                try:
                    # Use ast.literal_eval to safely parse Python literal
                    parsed = ast.literal_eval(input)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass
                
                # If that fails, try to parse as JSON
                try:
                    # Replace single quotes with double quotes for JSON
                    input = input.replace("'", '"')
                    return json.loads(input)
                except:
                    raise ValueError("Input string is neither valid Python literal nor JSON")
                    
            if isinstance(input, bytes):
                return json.loads(input.decode("utf-8"))
            if isinstance(input, dict):
                return input
            raise ValueError("Input must be JSON string, bytes, or dict")
    
        data = _parse_input(input).get("response", _parse_input(input)).get("result", _parse_input(input))
        data = data.get("apiResponse",data)
        
        default_value = True if data is not None else False

        license_purchased = data.get('licensePurchased', default_value)
        if not license_purchased:
            if 'totalRecords' in data:
                if data['totalRecords'] > 0:
                    license_purchased = True

        license_info = {
            "confirmedLicensePurchased": license_purchased
        }
        return license_info
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}
        