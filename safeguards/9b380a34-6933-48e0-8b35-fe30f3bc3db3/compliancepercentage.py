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
        
        total = len(passed) + len(failed)
        compliancePercentage = int((len(passed) / total) * 100) if total > 0 else 0

        compliance_percentage = {
            "compliancePercentage": compliancePercentage,
            "CIScompliancePercentage": compliancePercentage,
            "totalPassed": len(passed),
            "totalFailed": len(failed),
            "totalFindings": total,
            "passedFindings": passed,
            "failedFindings": failed
        }
        return compliance_percentage
    except Exception as e:
        return {"compliancePercentage": 0,"CIScompliancePercentage": 0, "error": str(e)}
        