def transform(input):
    """
    Evaluates the compliance percentage of the Cloud Security Compliance findings

    Parameters:
        input (dict): The JSON data containing Cloud Security Compliance findings.

    Returns:
        dict: A dictionary summarizing the compliance percentage.
    """

    try:
        # Initialize counters
        if 'response' in input:
            input = input['response']
        if 'Findings' in input:
            input = input['Findings']

        passed = [obj for obj in input if 'Compliance' in obj and 'Status' in obj['Compliance'] and str(obj['Compliance']['Status']).lower() == "passed"]
        failed = [obj for obj in input if 'Compliance' in obj and 'Status' in obj['Compliance'] and str(obj['Compliance']['Status']).lower() == "failed"]
        compliance_percentage = {
            "compliancePercentage": len(passed) / (len(passed) + len(failed)),
            "totalPassed": len(passed),
            "totalFailed": len(failed),
            "totalFindings": len(input),
            "passedFindings": passed,
            "failedFindings": failed
        }
        return compliance_percentage
    except Exception as e:
        return {"compliancePercentage": 0, "error": str(e)}
        