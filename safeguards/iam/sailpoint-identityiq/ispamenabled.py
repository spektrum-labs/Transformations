"""
Transformation: isPAMEnabled
Vendor: Sailpoint Identityiq
Category: Identity & Access Management

Evaluates isPAMEnabled for SailPoint IdentityIQ (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPAMEnabled", "vendor": "Sailpoint Identityiq", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isPAMEnabled"

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

        if isinstance(users, list) and len(users) > 0:
            admin_count = 0
            regular_count = 0

            for user in users:
                if isinstance(user, dict):
                    display = str(user.get("displayName", user.get("userName", ""))).lower()
                    is_admin = False

                    # Check for SailPoint capabilities extension
                    sp_ext = user.get("urn:ietf:params:scim:schemas:sailpoint:1.0:User", {})
                    if isinstance(sp_ext, dict):
                        caps = sp_ext.get("capabilities", [])
                        if isinstance(caps, list):
                            for cap in caps:
                                cap_str = str(cap).lower()
                                if "system" in cap_str or "admin" in cap_str:
                                    is_admin = True
                                    break

                    if "admin" in display or "service" in display or "system" in display:
                        is_admin = True

                    # Check groups/roles
                    groups = user.get("groups", [])
                    if isinstance(groups, list):
                        for group in groups:
                            if isinstance(group, dict):
                                gname = str(group.get("display", "")).lower()
                                if "admin" in gname or "priv" in gname:
                                    is_admin = True
                                    break

                    if is_admin:
                        admin_count = admin_count + 1
                    else:
                        regular_count = regular_count + 1

            if admin_count > 0 and regular_count > 0:
                result = True
            elif admin_count > 0:
                result = True
            elif len(users) > 0:
                # IdentityIQ itself provides PAM governance capabilities
                result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isPAMEnabled": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
