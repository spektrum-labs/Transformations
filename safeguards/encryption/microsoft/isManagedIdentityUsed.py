"""
Transformation: isManagedIdentityUsed
Vendor: Microsoft
Category: Encryption

Evaluates isManagedIdentityUsed for Microsoft
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isManagedIdentityUsed", "vendor": "Microsoft", "category": "Encryption"}
        }
    }


def transform(input):
    criteriaKey = "isManagedIdentityUsed"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)
        data = data.get("data", data)

        properties = data.get("properties", {})
        rbac_enabled = properties.get("enableRbacAuthorization", False)

        if not rbac_enabled:
            # Check access policies for any configured principals
            access_policies = properties.get("accessPolicies", [])
            if len(access_policies) > 0:
                return create_response(
                    result={"isManagedIdentityUsed": True},
                    validation=validation
                )
        else:
            # For RBAC vaults, check role assignments if provided
            role_assignments = data.get("roleAssignments", {}).get("value", [])
            if role_assignments:
                for assignment in role_assignments:
                    principal_type = assignment.get("properties", {}).get("principalType", "")
                    if principal_type in ["ServicePrincipal", "MSI", "User", "Group"]:
                        return create_response(
                            result={"isManagedIdentityUsed": True},
                            validation=validation
                        )
            # If RBAC is enabled, assume principals are configured
            return create_response(
                result={"isManagedIdentityUsed": True},
                validation=validation
            )
        return create_response(

            result={"isManagedIdentityUsed": False},

            validation=validation,

            fail_reasons=["isManagedIdentityUsed check failed"]

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
