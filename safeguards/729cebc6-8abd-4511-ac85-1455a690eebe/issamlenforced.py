import json
import ast
from datetime import datetime

def transform(input):
    """
    Evaluates the SAML enforcement status of the account.

    Parameters:
        input (str | dict): The JSON data containing SAML provider information. 
                            If a string is provided, it will be parsed.

    Returns:
        dict: A dictionary summarizing the SAML provider information.
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

        # Extract response safely
        data = _parse_input(input).get("response", _parse_input(input)).get("result", _parse_input(input))
        data = data.get("apiResponse",data)
        domains = data.get("value", [])
        
        # Construct the output
        is_saml_enforced = False
        for domain in domains:
            if domain.get("authenticationType", "managed").lower() == "federated":
                is_saml_enforced = True
                break

        return { "isSAMLEnforced": is_saml_enforced }

    except json.JSONDecodeError:
        return { "isSAMLEnforced": False, "error": "Invalid JSON format." }
    except Exception as e:
        return { "isSAMLEnforced": False, "error": str(e) }
