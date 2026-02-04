def transform(input):
    """
    Evaluates if the password policy is enforced via conditional access policies.

    Password policy is considered enforced when either:
    - An enabled Conditional Access policy blocks legacy authentication (e.g. Exchange
      ActiveSync, other legacy clients), or
    - An enabled policy has authentication strength configured (traditional password /
      strong authentication requirements).

    Parameters:
        input (dict): The JSON data from Microsoft Graph API conditional access policies endpoint
                      (https://graph.microsoft.com/beta/identity/conditionalAccess/policies)

    Returns:
        dict: A dictionary summarizing the password policy enforcement information.
    """
    # Legacy client app types targeted by "Block legacy authentication" policies
    legacy_client_app_types = ("exchangeActiveSync", "other")

    def is_legacy_auth_block_policy(policy):
        """True if enabled policy blocks legacy authentication (block + legacy clientAppTypes)."""
        if not isinstance(policy, dict):
            return False
        if policy.get("state", "").lower() != "enabled":
            return False
        grant_controls = policy.get("grantControls") or {}
        built_in = grant_controls.get("builtInControls") or []
        if "block" not in built_in:
            return False
        conditions = policy.get("conditions") or {}
        client_types = conditions.get("clientAppTypes") or []
        return any(t in client_types for t in legacy_client_app_types)

    def has_authentication_strength(policy):
        """True if enabled policy has authentication strength configured (e.g. MFA / strong auth)."""
        if not isinstance(policy, dict):
            return False
        if policy.get("state", "").lower() != "enabled":
            return False
        grant_controls = policy.get("grantControls") or {}
        auth_strength = grant_controls.get("authenticationStrength")
        if auth_strength is None or auth_strength == "None":
            return False
        if isinstance(auth_strength, dict) and auth_strength.get("id"):
            return True
        return False

    criteria_key_name = "confirmPasswordPolicyEnforced"
    criteria_key_result = False

    try:
        # Check if an error response body was returned
        if "error" in input:
            data_error = input.get("error")
            data_inner_error = data_error.get("innerError", {}) if data_error else {}
            return {
                criteria_key_name: False,
                "errorSource": "msgraph_api",
                "errorCode": data_error.get("code"),
                "errorMessage": data_error.get("message"),
                "innerErrorCode": data_inner_error.get("code") if data_inner_error else None,
                "innerErrorMessage": data_inner_error.get("message") if data_inner_error else None,
            }

        # Ensure value is type list, replace None if found
        value = input.get("value", [])
        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [value]

        # Find enabled policies that block legacy authentication
        legacy_block_policies = []
        # Find enabled policies with authentication strength (traditional password / strong auth)
        auth_strength_policies = []
        for policy in value:
            if is_legacy_auth_block_policy(policy):
                legacy_block_policies.append({
                    "id": policy.get("id", ""),
                    "displayName": policy.get("displayName", ""),
                    "state": policy.get("state", ""),
                    "type": "legacyAuthBlock",
                })
            elif has_authentication_strength(policy):
                auth_strength = (policy.get("grantControls") or {}).get("authenticationStrength") or {}
                auth_strength_policies.append({
                    "id": policy.get("id", ""),
                    "displayName": policy.get("displayName", ""),
                    "state": policy.get("state", ""),
                    "type": "authenticationStrength",
                    "authenticationStrengthDisplayName": auth_strength.get("displayName", ""),
                })

        # Enforced if either legacy auth is blocked or authentication strength is in place
        all_enforcing_policies = legacy_block_policies + auth_strength_policies
        criteria_key_result = len(all_enforcing_policies) > 0

        transformed_data = {
            criteria_key_name: criteria_key_result,
            "passwordPoliciesCount": len(all_enforcing_policies),
            "passwordPolicies": all_enforcing_policies,
            "legacyAuthBlockPoliciesCount": len(legacy_block_policies),
            "authenticationStrengthPoliciesCount": len(auth_strength_policies),
        }
        return transformed_data

    except Exception as e:
        import traceback
        import sys

        print("Exception occurred during transformation:", file=sys.stderr)
        traceback.print_exc()
        return {criteria_key_name: False, "error": str(e)}
