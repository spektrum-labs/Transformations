# issamlenforced.py - Rubrik

import json
import ast

def transform(input):
    """
    Checks cluster security configuration for SAML/SSO enforcement status.

    Parameters:
        input (dict): The JSON data from Rubrik getClusterInfo endpoint.

    Returns:
        dict: A dictionary summarizing the SAML/SSO enforcement status.
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

        is_saml_enforced = False

        # Check for explicit SAML/SSO enforcement flags
        if data.get('isSAMLEnforced') or data.get('samlEnforced'):
            is_saml_enforced = True

        if data.get('samlEnabled') or data.get('ssoEnabled'):
            is_saml_enforced = True

        # Check for security configuration
        security = data.get("security", {})
        if isinstance(security, dict):
            if security.get("samlEnabled") or security.get("ssoEnabled"):
                is_saml_enforced = True
            if security.get("samlEnforced") or security.get("isSAMLEnforced"):
                is_saml_enforced = True

        # Check for authentication configuration
        auth_config = data.get("authConfig", data.get("authentication", {}))
        if isinstance(auth_config, dict):
            if auth_config.get("saml") or auth_config.get("sso"):
                is_saml_enforced = True
            if auth_config.get("type", "").lower() in ["saml", "sso", "oauth"]:
                is_saml_enforced = True

        # Check for identity providers
        idp = data.get("identityProviders", data.get("idp", []))
        if isinstance(idp, list) and len(idp) > 0:
            is_saml_enforced = True
        elif isinstance(idp, dict) and idp:
            is_saml_enforced = True

        # Check SSO configuration
        sso_config = data.get("sso", data.get("ssoConfig", {}))
        if isinstance(sso_config, dict):
            if sso_config.get("enforced") or sso_config.get("enabled"):
                is_saml_enforced = True

        return {
            "isSAMLEnforced": is_saml_enforced
        }
    except Exception as e:
        return {"isSAMLEnforced": False, "error": str(e)}
