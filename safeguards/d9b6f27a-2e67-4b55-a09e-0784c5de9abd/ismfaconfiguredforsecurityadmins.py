def transform(input):
    """
    Evaluates if the MFA has been enabled for Security Administrator role

    Parameters:
        input (dict): The JSON data containing condititional access policies.

    Returns:
        dict: A dictionary summarizing if MFA has been enabled for the Security Administrator role.

    Comments:
        additional roles are:
        Role Name	                                    GUID (Role Template ID)
        Global Administrator	                        62e90394-69f5-4237-9190-012177145e10
        Privileged Role Administrator	                e8611ab8-c189-46e8-94e1-60213ab1f814
        Security Administrator	                        194ae4cb-b126-40b2-bd5b-6091b380977d
        Conditional Access Administrator	            b0f54661-2d74-4c50-afa3-1ec803f12efe
        Authentication Administrator	                c4e39d2d-7e9c-4c4c-8c1e-1f4fefb2a1d8
        User Administrator	                            fe930be7-5e62-47db-91af-98c3a49a38b1
        Helpdesk Administrator (Password Administrator)	729827e3-9c14-49f7-bb1b-9608f156bbb8
        Application Administrator	                    5b448b57-3eda-4d05-9e8d-0d63d8e3a6cf
        Cloud Application Administrator	                158c047a-c907-4f6f-bc65-8fbb3ee4d3d8
        Exchange Administrator	                        29232cdf-9323-42fd-ade2-1d097af3e4de
        SharePoint Administrator	                    29232cdf-9323-42fd-ade2-1d097af3e4de (same GUID used for multiple service admins)
        Teams Administrator	                            29232cdf-9323-42fd-ade2-1d097af3e4de
        Intune Administrator	                        f28a1f50-6e7c-4c8c-9c3b-1f5f9f8f6f0f


        For more information see:
        https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions?tabs=admin-center
    """

    # modify assignment to match specific criteriaKey
    criteriaKey = "isMFAEnforcedForSecurityAdminAccess"

    # default criteriaKey value
    criteriaValue = False

    policyCountTotal = 0

    endpoint_security_roles = [
        "62e90394-69f5-4237-9190-012177145e10"  # Security Administrator role GUID
    ]

    conditional_access_policies_for_endpoint_security_roles = []
    conditional_access_policies_not_for_endpoint_security_roles = []

    try:
        if 'value' in input:
            data = input['value']
        
        for policy in data:
            roles = policy.get("conditions", {}).get("users", {}).get("includeRoles", [])
            grant_controls = policy.get("grantControls", {}).get("builtInControls", [])

            # Check if policy applies to endpoint security roles AND requires MFA
            if any(role in endpoint_security_roles for role in roles):
                requires_mfa = "mfa" in grant_controls
                criteriaValue = True
                conditional_access_policies_for_endpoint_security_roles.append(policy.get("displayName"))
            else:
                conditional_access_policies_not_for_endpoint_security_roles.append(policy.get("displayName"))
            policyCountTotal += 1

        return {
            criteriaKey: criteriaValue,
            "policyCountTotal": policyCountTotal,
            "policyCountforSecurityRole": len(conditional_access_policies_for_endpoint_security_roles),
            "policyCountNotForSecurityRole": len(conditional_access_policies_not_for_endpoint_security_roles)
        }
    
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}
        
