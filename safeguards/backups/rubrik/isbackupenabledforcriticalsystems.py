# isbackupenabledforcriticalsystems.py - Rubrik

import json
import ast

def transform(input):
    """
    Calculates coverage percentage of backups for scoped critical systems
    using compliance summary data.

    Parameters:
        input (dict): The JSON data from Rubrik getComplianceSummary endpoint.

    Returns:
        dict: A dictionary with backup coverage information for critical systems.
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

        is_enabled_for_critical = False
        total_objects = 0
        compliant_count = 0
        non_compliant_count = 0
        coverage_percentage = 0.0

        # Get compliance counts from Rubrik compliance summary
        compliant_count = data.get("compliantCount", 0)
        non_compliant_count = data.get("nonCompliantCount", 0)
        total_objects = data.get("totalObjects", data.get("totalProtectedObjects", 0))

        # Calculate total if not provided
        if total_objects == 0:
            total_objects = compliant_count + non_compliant_count

        # Calculate coverage percentage
        if total_objects > 0:
            coverage_percentage = (compliant_count / total_objects) * 100
            is_enabled_for_critical = coverage_percentage >= 80  # 80% threshold

        # Check for explicit critical systems coverage
        if data.get("criticalSystemsCovered") or data.get("allCriticalProtected"):
            is_enabled_for_critical = True

        # Check for protected objects data
        protected_objects = data.get("protectedObjects", data.get("objects", []))
        if isinstance(protected_objects, list) and len(protected_objects) > 0:
            if total_objects == 0:
                total_objects = len(protected_objects)
                compliant_count = sum(
                    1 for obj in protected_objects
                    if isinstance(obj, dict) and obj.get("complianceStatus", "").lower() in ["compliant", "in_compliance"]
                )
                if total_objects > 0:
                    coverage_percentage = (compliant_count / total_objects) * 100
                    is_enabled_for_critical = coverage_percentage >= 80

        return {
            "isBackupEnabledForCriticalSystems": is_enabled_for_critical,
            "totalObjects": total_objects,
            "compliantCount": compliant_count,
            "nonCompliantCount": non_compliant_count,
            "coveragePercentage": round(coverage_percentage, 2)
        }

    except json.JSONDecodeError:
        return {"isBackupEnabledForCriticalSystems": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}
