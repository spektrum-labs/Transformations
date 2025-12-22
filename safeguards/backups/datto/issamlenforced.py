# issamlenforced.py - Datto BCDR

import json
import ast

def transform(input):
    """
    Evaluates if SAML/SSO is enforced for Datto BCDR portal access

    Parameters:
        input (dict): The JSON data containing SSO/SAML information.

    Returns:
        dict: A dictionary summarizing the SSO information.
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

        # Parse input
        data = _parse_input(input)
        data = data.get("response", data)
        data = data.get("result", data)
        data = data.get("apiResponse", data)
        
        default_value = True if data is not None else False

        # Check for SAML/SSO enforcement
        is_saml_enforced = (
            data.get('isSAMLEnforced', default_value) or
            data.get('samlEnabled', default_value) or
            data.get('ssoEnabled', default_value) or
            data.get('sso', {}).get('enforced', default_value)
        )
        
        sso_info = {
            "isSAMLEnforced": is_saml_enforced
        }
        return sso_info
    except Exception as e:
        return {"isSAMLEnforced": False, "error": str(e)}

