def transform(input):
    """
    Evaluates percentage of endpoint protection for eligible machines

    Parameters:
        input (dict): The JSON data containing machine information.

    Returns:
        dict: A dictionary summarizing endpoint protection.
    """

    # modify assignment to match specific criteriaKey
    criteriaKey = "requiredCoveragePercentage"

    # default criteriaKey value
    criteriaValue = False

    try:
        if 'value' in input:
            data = input['value']
        
        eligibleMachines = [m for m in data if not m["isExcluded"]]
        protectedMachines = [
           m for m in eligibleMachines
        if m["healthStatus"] == "Active" and m["onboardingStatus"] == "Onboarded"
        ]

        allDevices = len(data)
        eligibleDevices = len(eligibleMachines)
        protectedDevices = len(protectedMachines)

        criteriaValue = (eligibleDevices == protectedDevices)

        return {
            criteriaKey: criteriaValue,
            "allDevicesPercentageofCoverage": round((protectedDevices / allDevices) * 100),
            "eligibleDevicesPercentageofCoverage": round((protectedDevices / eligibleDevices) * 100),
            "allDevices": allDevices,
            "eligibleDevices": eligibleDevices,
            "protectedDevices": protectedDevices
        }
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}
        
