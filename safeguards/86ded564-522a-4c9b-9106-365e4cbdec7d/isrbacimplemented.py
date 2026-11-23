"""
Transformation: isRBACImplemented
Vendor: Generic IDP
Category: Identity / Access Control

Evaluates if Role-Based Access Control (RBAC) is implemented.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isRBACImplemented",
                "vendor": "Generic",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isRBACImplemented"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        # Wrong shape is not a finding. This file reads an object that carries an 'rbac' role
        # assignment list. Handed anything else -- a bare list (Okta's /api/v1/org/factors catalogue
        # of factor types was scored False for exactly this reason), a string, or an object with no
        # 'rbac' key -- the read cannot answer the check, so the verdict is None (Not evaluated)
        # with a reason, never False. dataCollection.status "error" (api_errors) is what makes
        # Token-Service grade the None as Not evaluated instead of Failed.
        # The 'rbac' value itself must be a list (or null, meaning no assignments). A string,
        # object or number in its place cannot answer the check either.
        rbac_ok = isinstance(data, dict) and 'rbac' in data and (data['rbac'] is None or isinstance(data['rbac'], list))
        if not rbac_ok:
            if isinstance(data, list):
                shape = "a list of " + str(len(data)) + " items"
            elif isinstance(data, dict) and 'rbac' not in data:
                shape = "an object without an 'rbac' key"
            elif isinstance(data, dict):
                v = data['rbac']
                kind = "text" if isinstance(v, str) else "an object" if isinstance(v, dict) else "a true/false value" if isinstance(v, bool) else "a number" if isinstance(v, (int, float)) else "another type"
                shape = "an object whose 'rbac' value is " + kind + ", not a list"
            else:
                shape = "not an object"
            reason = ("Not evaluated: the response is " + shape + ", not an object with an 'rbac' role "
                      "assignment list, so it cannot show whether RBAC is implemented")
            return create_response(
                result={criteriaKey: None},
                validation=validation,
                fail_reasons=[reason],
                api_errors=[reason]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        rbac = data.get('rbac') or []
        is_implemented = isinstance(rbac, list) and len(rbac) > 0

        if is_implemented:
            pass_reasons.append(f"RBAC is implemented with {len(rbac)} role assignments")
        else:
            fail_reasons.append("No RBAC role assignments found")
            recommendations.append("Implement Role-Based Access Control")

        return create_response(
            result={criteriaKey: is_implemented},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"rbacAssignments": len(rbac) if isinstance(rbac, list) else 0}
        )

    except Exception as e:
        # An error is Not evaluated, never a finding.
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"],
            api_errors=[f"Transformation error: {str(e)}"]
        )
