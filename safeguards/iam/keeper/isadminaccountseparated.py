def transform(input):
    """
    Validates that admin accounts are dedicated and separate from standard user accounts in Keeper.

    Evaluates Commander user-report or SCIM user data for admin account separation.
    Commander: user-report
    SCIM: GET /Users

    CIS Control 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts
    NIST AC-6(5): Privileged Accounts

    Parameters:
        input (dict): The JSON data from Keeper user-report or SCIM /Users response

    Returns:
        dict: A dictionary with the isAdminAccountSeparated evaluation result
    """
    criteria_key = "isAdminAccountSeparated"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']
        if 'data' in input:
            input = input['data']

        admin_separated = False
        separation_details = {
            "totalUsers": 0,
            "adminUsers": 0,
            "standardUsers": 0,
            "usersWithBothRoles": 0,
            "dedicatedAdminAccounts": 0,
            "separationCompliant": False
        }

        # Track users by email/username to detect dual accounts
        user_accounts = {}  # email -> list of account types

        # Check for admins list
        admins = input.get('admins', input.get('administrators', []))
        if isinstance(admins, list):
            separation_details["adminUsers"] = len(admins)
            for admin in admins:
                if isinstance(admin, dict):
                    email = admin.get('email', admin.get('username', ''))
                    if email:
                        if email not in user_accounts:
                            user_accounts[email] = []
                        user_accounts[email].append('admin')

        # Check users array
        users = input.get('users', input.get('Resources', []))
        if isinstance(users, list):
            separation_details["totalUsers"] = len(users)
            admin_count = 0
            standard_count = 0

            for user in users:
                if isinstance(user, dict):
                    email = user.get('email', user.get('userName', user.get('username', '')))

                    # Determine if admin
                    is_admin = user.get('is_admin', user.get('isAdmin', False))
                    role = user.get('role', user.get('userRole', '')).lower()
                    admin_roles = ['admin', 'administrator', 'root', 'owner', 'keeper administrator']

                    if is_admin or role in admin_roles:
                        admin_count += 1
                        if email:
                            if email not in user_accounts:
                                user_accounts[email] = []
                            user_accounts[email].append('admin')
                    else:
                        standard_count += 1
                        if email:
                            if email not in user_accounts:
                                user_accounts[email] = []
                            user_accounts[email].append('standard')

            separation_details["adminUsers"] = admin_count
            separation_details["standardUsers"] = standard_count

        # Check enterprise data for admin separation
        if 'enterprise' in input:
            enterprise = input['enterprise']
            if isinstance(enterprise, dict):
                admins_list = enterprise.get('admins', enterprise.get('administrators', []))
                if isinstance(admins_list, list):
                    separation_details["adminUsers"] = len(admins_list)
                    for admin in admins_list:
                        if isinstance(admin, dict):
                            email = admin.get('email', admin.get('username', ''))
                            if email:
                                if email not in user_accounts:
                                    user_accounts[email] = []
                                user_accounts[email].append('admin')

        # Check roles for admin identification
        if 'roles' in input:
            roles = input['roles']
            if isinstance(roles, list):
                for role in roles:
                    if isinstance(role, dict):
                        role_name = role.get('name', '').lower()
                        if 'admin' in role_name:
                            users_in_role = role.get('users', role.get('members', []))
                            if isinstance(users_in_role, list):
                                for user in users_in_role:
                                    email = user if isinstance(user, str) else user.get('email', '')
                                    if email:
                                        if email not in user_accounts:
                                            user_accounts[email] = []
                                        if 'admin' not in user_accounts[email]:
                                            user_accounts[email].append('admin')

        # Analyze account separation
        users_with_both = 0
        dedicated_admins = 0

        for email, account_types in user_accounts.items():
            if 'admin' in account_types and 'standard' in account_types:
                users_with_both += 1
            elif 'admin' in account_types and 'standard' not in account_types:
                dedicated_admins += 1

        separation_details["usersWithBothRoles"] = users_with_both
        separation_details["dedicatedAdminAccounts"] = dedicated_admins

        # Determine compliance
        # Compliant if: all admin accounts are dedicated (no dual-use)
        if separation_details["adminUsers"] > 0:
            if users_with_both == 0:
                admin_separated = True
                separation_details["separationCompliant"] = True
            else:
                # Calculate compliance percentage
                total_admins = separation_details["adminUsers"]
                if total_admins > 0:
                    compliance = ((total_admins - users_with_both) / total_admins) * 100
                    separation_details["compliancePercentage"] = round(compliance, 2)
        else:
            # No admins found - could be SCIM limited data
            # Check if we have any indication of admin separation policy
            if 'enforcement' in input:
                enforcement = input['enforcement']
                if isinstance(enforcement, dict):
                    if enforcement.get('dedicated_admin_accounts', False) or \
                       enforcement.get('admin_separation', False):
                        admin_separated = True
                        separation_details["separationCompliant"] = True
                        separation_details["enforcedByPolicy"] = True

        # Check for admin separation policy
        if 'policies' in input:
            policies = input['policies']
            if isinstance(policies, list):
                for policy in policies:
                    if isinstance(policy, dict):
                        if policy.get('type', '').lower() in ['admin_separation', 'privileged_access']:
                            if policy.get('enabled', False):
                                admin_separated = True
                                separation_details["enforcedByPolicy"] = True

        return {
            criteria_key: admin_separated,
            **separation_details
        }

    except Exception as e:
        return {criteria_key: False, "error": str(e)}
