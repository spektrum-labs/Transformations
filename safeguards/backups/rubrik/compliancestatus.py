# compliancestatus.py - Rubrik

import json
import ast

def transform(input):
    """
    Calculates overall compliance percentage from compliant vs non-compliant
    object counts.

    Parameters:
        input (dict): The JSON data from Rubrik getComplianceSummary endpoint.

    Returns:
        dict: A dictionary with compliance status information.
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

        is_compliant = False
        compliant_count = 0
        non_compliant_count = 0
        total_objects = 0
        compliance_percentage = 0.0

        # Get compliance counts from Rubrik compliance summary
        compliant_count = data.get("compliantCount", 0)
        non_compliant_count = data.get("nonCompliantCount", 0)
        total_objects = data.get("totalObjects", data.get("totalProtectedObjects", 0))

        # Calculate total if not provided
        if total_objects == 0:
            total_objects = compliant_count + non_compliant_count

        # Calculate compliance percentage
        if total_objects > 0:
            compliance_percentage = (compliant_count / total_objects) * 100
            is_compliant = compliance_percentage >= 80  # 80% threshold for overall compliance

        # Check for explicit compliance status
        if data.get("isCompliant") or data.get("complianceStatus", "").lower() == "compliant":
            is_compliant = True

        # Check for SLA compliance data
        sla_compliance = data.get("slaCompliance", [])
        if isinstance(sla_compliance, list) and len(sla_compliance) > 0:
            sla_compliant = 0
            sla_total = len(sla_compliance)
            for sla in sla_compliance:
                if isinstance(sla, dict):
                    if sla.get("complianceStatus", "").lower() in ["compliant", "in_compliance"]:
                        sla_compliant += 1
                    if sla.get("compliantCount", 0) > 0 and sla.get("nonCompliantCount", 0) == 0:
                        sla_compliant += 1
            if sla_total > 0 and (sla_compliant / sla_total) >= 0.8:
                is_compliant = True

        return {
            "complianceStatus": is_compliant,
            "compliantCount": compliant_count,
            "nonCompliantCount": non_compliant_count,
            "totalObjects": total_objects,
            "compliancePercentage": round(compliance_percentage, 2)
        }

    except json.JSONDecodeError:
        return {"complianceStatus": False, "error": "Invalid JSON"}
    except Exception as e:
        return {"complianceStatus": False, "error": str(e)}
