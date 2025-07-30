import json
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
        # Ensure input is a dictionary by parsing if necessary
        if isinstance(input, str):
            input = json.loads(input)  # Convert JSON string to dictionary
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))  # Decode bytes then parse JSON
        
        if not isinstance(input, dict):
            raise ValueError("JSON input must be an object (dictionary).")

        # Extract response safely
        saml_providers = input.get("ListSAMLProvidersResponse", []).get("ListSAMLProvidersResult", {}).get("SAMLProviderList", []).get("member", [])
        
        # Construct the output
        is_saml_enforced = False
        for provider in saml_providers:
            validUntil = provider.get("ValidUntil", "")
            if validUntil != "":
                # Convert ValidUntil to datetime and compare with today
                valid_until_date = datetime.strptime(validUntil, "%Y-%m-%dT%H:%M:%SZ")
                if valid_until_date > datetime.utcnow():
                    is_saml_enforced = True
                    break

        return { "isSAMLEnforced": is_saml_enforced }

    except json.JSONDecodeError:
        return { "isSAMLEnforced": False, "error": "Invalid JSON format." }
    except Exception as e:
        return { "isSAMLEnforced": False, "error": str(e) }
