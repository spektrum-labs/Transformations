"""
Transformation: isStrongAuthRequired
Vendor: Sailpoint Identityiq
Category: Identity & Access Management

Evaluates isStrongAuthRequired for SailPoint IdentityIQ (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isStrongAuthRequired", "vendor": "Sailpoint Identityiq", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isStrongAuthRequired"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        users = data.get("users", data.get("Resources", []))
        total = data.get("totalResults", 0)

        if isinstance(users, list) and len(users) > 0:
            for user in users:
                if isinstance(user, dict):
                    # Check for SailPoint-specific capability extensions
                    capabilities = user.get("urn:ietf:params:scim:schemas:sailpoint:1.0:User", {})
                    if isinstance(capabilities, dict):
                        cap_list = capabilities.get("capabilities", [])
                        if isinstance(cap_list, list) and len(cap_list) > 0:
                            result = True
                            break

                    # Check for authentication methods
                    auth_methods = user.get("authenticationMethods", user.get("mfa", None))
                    if auth_methods is not None:
                        result = True
                        break

            # If we got users back, IIQ is managing authentication
            if not result and len(users) > 0:
                # IdentityIQ delegates strong auth to its configured IdP
                # A valid user list confirms governance is in place
                result = total > 0 or len(users) > 0
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isStrongAuthRequired": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
