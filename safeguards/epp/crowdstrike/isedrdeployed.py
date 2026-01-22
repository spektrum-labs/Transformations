def transform(input):
    """
    EDR or XDR solutions deployed on % of endpoints

    Parameters:
        input (dict): The JSON data containing crowdstrike API response

    Returns:
        dict: A dictionary with the isEDRDeployed evaluation result
    """

    criteria_key = "isEDRDeployed"

    try:
        # Handle nested response structures
        if 'response' in input:
            input = input['response']
        if 'apiResponse' in input:
            input = input['apiResponse']
        if 'result' in input:
            input = input['result']

        # Calculate deployment/coverage metrics
        total_count = 0
        deployed_count = 0
        coverage_percentage = 0.0

        # Check for common data structures
        if 'devices' in input:
            devices = input['devices'] if isinstance(input['devices'], list) else []
            total_count = len(devices)
            deployed_count = len([d for d in devices if d.get('status') in ['active', 'protected', 'deployed']])
        elif 'endpoints' in input:
            endpoints = input['endpoints'] if isinstance(input['endpoints'], list) else []
            total_count = len(endpoints)
            deployed_count = len([e for e in endpoints if e.get('status') in ['active', 'protected', 'deployed']])
        elif 'hosts' in input:
            hosts = input['hosts'] if isinstance(input['hosts'], list) else []
            total_count = len(hosts)
            deployed_count = len([h for h in hosts if h.get('status') in ['active', 'protected', 'deployed']])
        elif 'total' in input and 'deployed' in input:
            total_count = int(input.get('total', 0))
            deployed_count = int(input.get('deployed', 0))
        elif 'totalEndpoints' in input and 'protectedEndpoints' in input:
            total_count = int(input.get('totalEndpoints', 0))
            deployed_count = int(input.get('protectedEndpoints', 0))

        # Calculate percentage
        if total_count > 0:
            coverage_percentage = (deployed_count / total_count) * 100

        # Typically consider deployed if >80% coverage
        is_deployed = coverage_percentage >= 80.0

        return {
            criteria_key: is_deployed,
            "totalCount": total_count,
            "deployedCount": deployed_count,
            "coveragePercentage": round(coverage_percentage, 2)
        }

    except Exception as e:
        return {
            criteria_key: False,
            "error": str(e)
        }
