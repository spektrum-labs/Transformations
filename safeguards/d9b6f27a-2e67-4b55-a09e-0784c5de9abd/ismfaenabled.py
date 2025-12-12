def transform(input):
    """
    Evaluates if the MFA is enabled for environment

    Parameters:
        input (dict): The JSON data containing conditional access information.

    Returns:
        dict: A dictionary summarizing if MFA is enabled for environment.
    """

    # modify assignment to match specific criteriaKey
    criteriaKey = "isMFAEnabled"

    # default criteriaKey value
    criteriaValue = False

    ca_policy_count = 0
    ca_policy_with_mfa_count = 0
    ca_policy_without_mfa_count = 0

    try:
        if 'value' in input:
            data = input['value']
        
        conditional_access_policies_with_mfa = []
        conditional_access_policies_without_mfa = []
        conditional_access_policy_names_with_mfa = []
        conditional_access_policy_names_without_mfa = []
        for policy in data:
            built_in_controls = policy.get("grantControls", {}).get("builtInControls", [])

            requires_mfa = "mfa" in built_in_controls

            if (requires_mfa):
                conditional_access_policies_with_mfa.append(policy)
                conditional_access_policy_names_with_mfa.append(policy.get("displayName"))
                ca_policy_with_mfa_count += 1
                criteriaValue = True

            else:
                conditional_access_policies_without_mfa.append(policy)
                conditional_access_policy_names_without_mfa.append(policy.get("displayName"))
                ca_policy_without_mfa_count += 1
            ca_policy_count += 1

        return {
            criteriaKey: criteriaValue,
            "policiesTotal": ca_policy_count,
            "policiesWithMFA": ca_policy_with_mfa_count,
            "policiesWithoutMFA": ca_policy_without_mfa_count,
            "conditionalAccessPoliciesWithMFA": conditional_access_policy_names_with_mfa,
            "conditionalAccessPoliciesWithoutMFA": conditional_access_policy_names_without_mfa
        }
    
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}