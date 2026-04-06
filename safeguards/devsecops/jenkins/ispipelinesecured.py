import json
import ast


def transform(input):
    """
    Evaluates isPipelineSecured for Jenkins

    Checks: Whether Jenkins security configuration and authorization policies are enabled
    API Source: {baseURL}/configureSecurity/api/json
    Pass Condition: Security realm and authorization strategy are configured (not unsecured)

    Parameters:
        input (dict): JSON data containing API response

    Returns:
        dict: {"isPipelineSecured": boolean, "securityEnabled": boolean, "authorizationStrategy": str}
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
        use_security = data.get("useSecurity", False)
        auth_strategy = data.get("authorizationStrategy", {})
        security_realm = data.get("securityRealm", {})

        strategy_name = ""
        if isinstance(auth_strategy, dict):
            strategy_name = auth_strategy.get("_class", auth_strategy.get("type", "unknown"))
        elif isinstance(auth_strategy, str):
            strategy_name = auth_strategy

        is_unsecured = "unsecured" in strategy_name.lower() if strategy_name else True

        result = use_security and not is_unsecured and bool(security_realm)
        # -- END EVALUATION LOGIC --

        return {
            "isPipelineSecured": result,
            "securityEnabled": use_security,
            "authorizationStrategy": strategy_name
        }

    except Exception as e:
        return {"isPipelineSecured": False, "error": str(e)}
