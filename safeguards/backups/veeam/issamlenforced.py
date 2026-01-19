# issamlenforced.py - Veeam VSPC

import json
import ast

def transform(input):
    """
    Evaluates if SAML/SSO is enforced for Veeam Service Provider Console access.

    Parameters:
        input (dict): The JSON data from Veeam SAML providers endpoint.

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
        provider_count = 0

        # Check for explicit SAML/SSO enforcement flags
        if data.get('isSAMLEnforced') or data.get('samlEnforced'):
            is_saml_enforced = True

        if data.get('samlEnabled') or data.get('ssoEnabled'):
            is_saml_enforced = True

        # Check for SAML providers list
        providers = (
            data.get("items", []) or
            data.get("providers", []) or
            data.get("samlProviders", []) or
            data.get("data", [])
        )

        if isinstance(providers, list):
            provider_count = len(providers)

            if provider_count > 0:
                # Check if any provider is enabled
                for provider in providers:
                    if isinstance(provider, list):
                        provider = provider[0] if len(provider) > 0 else {}

                    is_enabled = (
                        provider.get("isEnabled", True) or
                        provider.get("enabled", True) or
                        provider.get("status", "").lower() in ["active", "enabled"]
                    )

                    if is_enabled:
                        is_saml_enforced = True
                        break

        # Check SSO configuration
        sso_config = data.get("sso", data.get("ssoConfig", {}))
        if isinstance(sso_config, dict):
            if sso_config.get("enforced") or sso_config.get("enabled"):
                is_saml_enforced = True

        return {
            "isSAMLEnforced": is_saml_enforced,
            "samlProviderCount": provider_count
        }
    except Exception as e:
        return {"isSAMLEnforced": False, "error": str(e)}
